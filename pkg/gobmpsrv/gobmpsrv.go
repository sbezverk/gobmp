package gobmpsrv

import (
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/message"
	"github.com/sbezverk/gobmp/pkg/parser"
	"github.com/sbezverk/gobmp/pkg/pub"
)

// maxBMPMessagePayload is the maximum allowed BMP message payload size (1 MB).
const maxBMPMessagePayload = 1 << 20

// BMPServer defines methods to manage BMP Server
type BMPServer interface {
	Start()
	Stop()
}

type bmpServer struct {
	splitAF         bool
	intercept       bool
	publisher       pub.Publisher
	sourcePort      int
	destinationPort int
	incoming        net.Listener
	wg              sync.WaitGroup        // tracks server() + in-flight bmpWorker goroutines
	mu              sync.Mutex            // protects clients and closing
	clients         map[net.Conn]struct{} // active bmpWorker connections
	closing         bool                  // set to true in Stop() before iterating clients
	bmpRaw          bool
	adminID         string
}

func (srv *bmpServer) Start() {
	// Starting bmp server server
	glog.Infof("Starting gobmp server on %s, intercept mode: %t\n", srv.incoming.Addr().String(), srv.intercept)
	srv.wg.Add(1)
	go srv.server()
}

func (srv *bmpServer) Stop() {
	glog.Infof("Stopping gobmp server\n")
	// 1. Stop accepting new connections.
	_ = srv.incoming.Close()
	// 2. Set the closing flag and close every active client connection atomically
	//    under mu.  startWorker checks this flag (also under mu) so any connection
	//    that races through Accept() after this point is closed immediately there,
	//    preventing a missed-close / wg.Wait() hang.
	srv.mu.Lock()
	srv.closing = true
	for c := range srv.clients {
		_ = c.Close()
	}
	srv.mu.Unlock()
	// 3. Wait for server() and all bmpWorker goroutines to finish.
	srv.wg.Wait()
	// 4. Now it is safe to stop the publisher.
	if srv.publisher != nil {
		srv.publisher.Stop()
	}
}

func (srv *bmpServer) server() {
	defer srv.wg.Done()
	for {
		client, err := srv.incoming.Accept()
		if err != nil {
			// net.ErrClosed is returned when the listener has been closed,
			// which is exactly what Stop() does. Treat it as a clean shutdown.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			glog.Errorf("fail to accept client connection with error: %+v", err)
			continue
		}
		glog.V(5).Infof("client %+v accepted, calling bmpWorker", client.RemoteAddr())
		srv.startWorker(client)
	}
}

// startWorker registers the new connection with the WaitGroup and the active
// client set, then spawns a bmpWorker goroutine.
//
// Both the wg.Add and the map insertion are performed under mu, the same lock
// that Stop() holds when it sets closing=true and iterates the clients map.
// This eliminates the race where a connection accepted just after Stop() closes
// the listener would be added to the map after Stop() already iterated it:
//
//   - If startWorker acquires mu first → connection enters the map; Stop() will
//     close it when it iterates clients.
//   - If Stop() acquires mu first (sets closing=true, iterates) → startWorker
//     sees closing=true, closes the connection immediately, and returns without
//     touching the WaitGroup.
func (srv *bmpServer) startWorker(client net.Conn) {
	srv.mu.Lock()
	if srv.closing {
		srv.mu.Unlock()
		_ = client.Close()
		return
	}
	srv.wg.Add(1)
	srv.clients[client] = struct{}{}
	srv.mu.Unlock()
	go func() {
		defer func() {
			srv.mu.Lock()
			delete(srv.clients, client)
			srv.mu.Unlock()
			srv.wg.Done()
		}()
		srv.bmpWorker(client)
	}()
}

// isCleanClose reports whether err represents a normal connection close:
// the peer hung up (io.EOF) or Stop() closed the connection from our side
// (net.ErrClosed). io.ErrUnexpectedEOF is intentionally excluded: on the
// payload read path it indicates a truncated BMP frame and should be logged
// as an error.
func isCleanClose(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed)
}

func (srv *bmpServer) bmpWorker(client net.Conn) {
	defer func() {
		_ = client.Close()
	}()
	var server net.Conn
	var err error
	if srv.intercept {
		server, err = net.Dial("tcp", ":"+strconv.Itoa(srv.destinationPort))
		if err != nil {
			glog.Errorf("failed to connect to destination with error: %+v", err)
			return
		}
		defer func() { _ = server.Close() }()
		glog.V(5).Infof("connection to destination server %v established, start intercepting", server.RemoteAddr())
	}
	prod := message.NewProducer(srv.publisher, srv.splitAF)

	// Configure producer with admin ID for RAW message support
	if err := prod.SetConfig(&message.Config{
		AdminID: srv.adminID,
	}); err != nil {
		glog.Errorf("failed to configure producer with error: %+v", err)
		return
	}

	prodStop := make(chan struct{})
	producerQueue := make(chan bmp.Message)
	// Starting messages producer per client with dedicated work queue
	go prod.Producer(producerQueue, prodStop)

	// Extract speaker IP from the TCP connection. Set on all BMP messages
	// to provide a consistent router identity regardless of message type.
	// Type-assert to *net.TCPAddr to get a clean IP string free of
	// ports, brackets, and IPv6 zone identifiers.
	var speakerIP string
	if tcpAddr, ok := client.RemoteAddr().(*net.TCPAddr); ok && tcpAddr.IP != nil {
		speakerIP = tcpAddr.IP.String()
	} else {
		var host string
		host, _, err = net.SplitHostPort(client.RemoteAddr().String())
		if err != nil {
			addrStr := client.RemoteAddr().String()
			if ip := net.ParseIP(addrStr); ip != nil {
				speakerIP = ip.String()
			} else {
				glog.Warningf("failed to extract plain IP from remote address %q: %+v", addrStr, err)
			}
		} else {
			// Strip zone identifier from IPv6 link-local addresses (e.g. fe80::1%eth0).
			if h, _, ok := strings.Cut(host, "%"); ok {
				host = h
			}
			if ip := net.ParseIP(host); ip != nil {
				speakerIP = ip.String()
			} else {
				glog.Warningf("failed to normalize speaker IP from remote address %q", client.RemoteAddr().String())
			}
		}
	}

	parserQueue := make(chan []byte)
	parsStop := make(chan struct{})
	// Starting parser per client with dedicated work queue
	parserConfig := &parser.Config{
		EnableRawMode: srv.bmpRaw,
		SpeakerIP:     speakerIP,
	}
	p := parser.NewParser(parserQueue, producerQueue, parsStop, parserConfig)
	go p.Start()
	defer func() {
		glog.V(5).Infof("all done with client %+v", client.RemoteAddr())
		close(parsStop)
		close(prodStop)
	}()
	var headerBuf [bmp.CommonHeaderLength]byte
	for {
		// Read the fixed-size common header into a stack-allocated array — no heap alloc.
		if _, err := io.ReadFull(client, headerBuf[:]); err != nil {
			// io.ErrUnexpectedEOF here means the peer closed mid-header (e.g.
			// Stop() interrupted an in-flight read), which is a clean exit.
			if isCleanClose(err) || errors.Is(err, io.ErrUnexpectedEOF) {
				glog.V(5).Infof("client %+v closed connection: %+v", client.RemoteAddr(), err)
			} else {
				glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			}
			return
		}
		// Recovering common header first
		header, err := bmp.UnmarshalCommonHeader(headerBuf[:])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			return
		}
		// Validate message length before allocating (prevents resource exhaustion on corrupted data).
		totalLen, err := header.IntMessageLength()
		if err != nil {
			glog.Errorf("invalid message length from client %+v: %+v", client.RemoteAddr(), err)
			return
		}
		msgLen := totalLen - bmp.CommonHeaderLength
		if msgLen < 0 || msgLen > maxBMPMessagePayload {
			glog.Errorf("invalid message length %d from client %+v, closing connection", header.MessageLength, client.RemoteAddr())
			return
		}
		// A zero-length payload is valid only for Initiation and Termination,
		// which may carry an empty TLV section (RFC 7854 §4.3 / §4.5).
		// All other message types require at least a Per-Peer Header; a
		// zero-payload frame for them is structurally malformed and closing
		// the connection prevents cheap log/CPU spam without useful data.
		if msgLen == 0 && header.MessageType != bmp.InitiationMsg && header.MessageType != bmp.TerminationMsg {
			glog.Errorf("zero-length payload not valid for BMP message type %d from client %+v, closing connection", header.MessageType, client.RemoteAddr())
			return
		}
		// Single allocation for the full message; read payload directly into it.
		// When msgLen == 0 the slice is header-only and ReadFull is a no-op.
		fullMsg := make([]byte, totalLen)
		copy(fullMsg, headerBuf[:])
		if _, err := io.ReadFull(client, fullMsg[bmp.CommonHeaderLength:]); err != nil {
			// io.ErrUnexpectedEOF here means the peer sent a valid header but
			// disconnected before delivering the full payload — a truncated BMP
			// frame, which is a protocol error and should be logged accordingly.
			if isCleanClose(err) {
				glog.V(5).Infof("client %+v closed connection: %+v", client.RemoteAddr(), err)
			} else {
				glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			}
			return
		}
		// Sending information to the server only in intercept mode
		if srv.intercept {
			if _, err := server.Write(fullMsg); err != nil {
				glog.Errorf("fail to write to server %+v with error: %+v", server.RemoteAddr(), err)
				return
			}
		}
		parserQueue <- fullMsg
	}
}

// NewBMPServer instantiates a new instance of BMP Server
func NewBMPServer(sPort, dPort int, intercept bool, p pub.Publisher, splitAF bool, bmpRaw bool, adminID string) (BMPServer, error) {
	incoming, err := net.Listen("tcp", ":"+strconv.Itoa(sPort))
	if err != nil {
		glog.Errorf("fail to setup listener on port %d with error: %+v", sPort, err)
		return nil, err
	}
	bmpSrv := bmpServer{
		clients:         make(map[net.Conn]struct{}),
		sourcePort:      sPort,
		destinationPort: dPort,
		intercept:       intercept,
		publisher:       p,
		incoming:        incoming,
		splitAF:         splitAF,
		bmpRaw:          bmpRaw,
		adminID:         adminID,
	}

	return &bmpSrv, nil
}
