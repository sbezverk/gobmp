package gobmpsrv

import (
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/message"
	"github.com/sbezverk/gobmp/pkg/parser"
	"github.com/sbezverk/gobmp/pkg/pub"
)

const (
	// parserQueueDepth is the number of raw BMP messages buffered between the
	// TCP reader and the parser goroutine. A non-zero buffer decouples network
	// I/O from parsing so that a momentary parse stall (e.g. a GC pause) does
	// not stall the read loop. The value is intentionally small: with a 1 MB
	// per-message ceiling, 8 slots caps the worst-case per-connection memory to
	// ~8 MB. In practice, most BMP messages are order-of-magnitude smaller
	// (hundreds of bytes to a few KB), so the effective budget is much lower.
	// Increasing this beyond a small single digit offers diminishing decoupling
	// returns while raising the memory-exhaustion risk with many concurrent clients.
	parserQueueDepth = 8
)

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
	stop            chan struct{}
	bmpRaw          bool
	adminID         string
}

func (srv *bmpServer) Start() {
	// Starting bmp server server
	glog.Infof("Starting gobmp server on %s, intercept mode: %t\n", srv.incoming.Addr().String(), srv.intercept)
	go srv.server()
}

func (srv *bmpServer) Stop() {
	glog.Infof("Stopping gobmp server\n")
	if srv.publisher != nil {
		srv.publisher.Stop()
	}
	// Closing the listener unblocks server()'s Accept() call so that goroutine exits cleanly.
	_ = srv.incoming.Close()
	close(srv.stop)
}

func (srv *bmpServer) server() {
	for {
		client, err := srv.incoming.Accept()
		if err != nil {
			// net.ErrClosed is returned when the listener has been closed,
			// which is exactly what Stop() does. Treat it as a clean shutdown
			// regardless of whether srv.stop has been closed yet, avoiding
			// log spam from the race between closing the listener and the channel.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			glog.Errorf("fail to accept client connection with error: %+v", err)
			continue
		}
		glog.V(5).Infof("client %+v accepted, calling bmpWorker", client.RemoteAddr())
		go srv.bmpWorker(client)
	}
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

	parserQueue := make(chan []byte, parserQueueDepth)
	parsStop := make(chan struct{})
	// Starting parser per client with dedicated work queue
	parserConfig := &parser.Config{
		EnableRawMode: srv.bmpRaw,
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
			glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			return
		}
		// Recovering common header first
		header, err := bmp.UnmarshalCommonHeader(headerBuf[:])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			return
		}
		// Validate message length before allocating (prevents resource exhaustion on corrupted data).
		// msgLen < 0 means MessageLength is less than the header size — structurally impossible and
		// rejected immediately. msgLen == 0 is allowed: BMP Initiation and Termination messages may
		// legitimately carry no TLV body (RFC 7854 §4.3 / §4.5).
		totalLen, err := header.IntMessageLength()
		if err != nil {
			glog.Errorf("invalid message length from client %+v: %+v", client.RemoteAddr(), err)
			return
		}
		msgLen := totalLen - bmp.CommonHeaderLength
		if msgLen < 0 || msgLen > 1<<20 { // Max 1MB per BMP message
			glog.Errorf("invalid message length %d from client %+v, closing connection", header.MessageLength, client.RemoteAddr())
			return
		}
		// Single allocation for the full message; read payload directly into it.
		// When msgLen == 0 the slice is header-only and ReadFull is a no-op.
		fullMsg := make([]byte, totalLen)
		copy(fullMsg, headerBuf[:])
		if _, err := io.ReadFull(client, fullMsg[bmp.CommonHeaderLength:]); err != nil {
			glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
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
	bmp := bmpServer{
		stop:            make(chan struct{}),
		sourcePort:      sPort,
		destinationPort: dPort,
		intercept:       intercept,
		publisher:       p,
		incoming:        incoming,
		splitAF:         splitAF,
		bmpRaw:          bmpRaw,
		adminID:         adminID,
	}

	return &bmp, nil
}
