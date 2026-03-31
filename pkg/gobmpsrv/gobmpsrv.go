package gobmpsrv

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/config"
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
	// isActive selects the operating mode:
	//   false (default) — passive: bind a TCP listener and wait for routers to
	//                     connect and send BMP sessions.
	//   true            — active: initiate TCP connections to a known set of
	//                     BGP speakers listed in bgpSpeakers.
	isActive  bool
	splitAF   bool
	publisher pub.Publisher
	incoming  net.Listener   // passive mode only; nil in active mode
	wg        sync.WaitGroup // tracks server()/connector() + in-flight bmpWorker goroutines
	mu        sync.Mutex     // protects clients and closing
	stopOnce  sync.Once
	clients   map[net.Conn]struct{} // active bmpWorker connections
	closing   bool                  // set to true in Stop() before iterating clients
	bmpRaw    bool
	adminID   string
	// Active-mode fields — all nil/zero in passive mode.
	connectorStopCh chan struct{}      // closed by stopConnector() to signal connector() to exit
	bgpSpeakers     []string           // list of "host:port" addresses to dial
	connectorCtx    context.Context    // parent context for all dials; cancelled by stopConnector()
	connectorCancel context.CancelFunc // cancels connectorCtx
}

func (srv *bmpServer) Start() {
	// Starting bmp server
	srv.wg.Add(1)
	if srv.isActive {
		glog.Infof("Starting gobmp server in Active mode")
		go srv.connector()
	} else {
		glog.Infof("Starting gobmp server on %s", srv.incoming.Addr().String())
		go srv.server()
	}
}

func (srv *bmpServer) Stop() {
	glog.Infof("Stopping gobmp server")
	if srv.isActive {
		srv.stopConnector()
	} else {
		// 1. Stop accepting new connections.
		_ = srv.incoming.Close()
	}
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
	var err error
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
		if msgLen > maxBMPMessagePayload {
			glog.Errorf("BMP message too large from client %+v: totalLen=%d, payloadLen=%d, limit=%d; closing connection",
				client.RemoteAddr(), totalLen, msgLen, maxBMPMessagePayload)
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
		parserQueue <- fullMsg
	}
}

// bgpSpeaker tracks the connection state and reconnection backoff for a single
// BGP speaker in active mode. All fields except Address are protected by mu.
type bgpSpeaker struct {
	Address     string
	mu          sync.Mutex
	isConnected bool          // true while a bmpWorker goroutine owns the connection
	lastAttempt time.Time     // time of the most recent dial attempt
	retryDelay  time.Duration // current backoff delay; doubles on each failure up to 5 minutes
}

// stopConnector signals the connector goroutine to exit and cancels any
// in-progress dial. It is a no-op in passive mode and safe to call multiple
// times (guarded by stopOnce).
func (srv *bmpServer) stopConnector() {
	if !srv.isActive {
		return
	}
	srv.stopOnce.Do(func() {
		// Cancel connectorCtx first so any in-flight DialContext returns
		// immediately rather than waiting out its 5-second timeout.
		srv.connectorCancel()
		close(srv.connectorStopCh)
	})
}

// connector is the active-mode counterpart of server(). It runs as a single
// goroutine (tracked by srv.wg) and manages outbound TCP connections to the
// configured BGP speakers.
//
// For each speaker the loop:
//  1. Skips the speaker if it is already connected (bmpWorker goroutine running).
//  2. Waits until the per-speaker retry delay has elapsed (exponential backoff,
//     starting at 1 s, doubling on each failure, capped at 5 minutes).
//  3. Dials the speaker with a 5-second timeout derived from connectorCtx so
//     that Stop() can interrupt an in-progress dial immediately.
//  4. On success: registers the connection in srv.clients under srv.mu (the
//     same lock Stop() holds when it iterates the map), then spawns a
//     bmpWorker goroutine that processes BMP frames exactly as in passive mode.
//     When bmpWorker returns the goroutine marks the speaker as disconnected,
//     making it eligible for reconnection on the next loop iteration.
//  5. On failure: applies exponential backoff and continues to the next speaker.
//
// The outer loop sleeps 200 ms between full sweeps to avoid a busy-wait when
// all speakers are either connected or in their backoff window.
func (srv *bmpServer) connector() {
	speakers := make(map[string]*bgpSpeaker)
	for _, addr := range srv.bgpSpeakers {
		// Zero lastAttempt so time.Since(lastAttempt) ≫ retryDelay on the very
		// first iteration, causing an immediate connection attempt at startup.
		speakers[addr] = &bgpSpeaker{Address: addr, retryDelay: 1 * time.Second}
	}
	defer srv.wg.Done()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		for _, speaker := range speakers {
			// Check for stop signal before each per-speaker iteration so the
			// loop exits promptly when Stop() is called.
			select {
			case <-srv.connectorStopCh:
				glog.Infof("connector received stop signal, exiting")
				return
			default:
			}

			speaker.mu.Lock()
			if !speaker.isConnected && time.Since(speaker.lastAttempt) >= speaker.retryDelay {
				glog.Infof("Attempting to connect to BGP speaker %s", speaker.Address)
				// Release speaker.mu before dialling: the dial may block for up
				// to 5 seconds and we must not hold the lock across I/O.
				speaker.mu.Unlock()

				// Derive a timeout context from connectorCtx so that
				// stopConnector() (which cancels connectorCtx) also aborts
				// any dial that is currently in progress.
				ctx, cancel := context.WithTimeout(srv.connectorCtx, 5*time.Second)
				client, err := (&net.Dialer{}).DialContext(ctx, "tcp", speaker.Address)
				cancel() // always release the timer goroutine regardless of outcome

				if err == nil {
					// Hold srv.mu for the entire block that checks srv.closing,
					// updates speaker state, increments the WaitGroup, and inserts
					// the connection into srv.clients. Doing all of this atomically
					// under one lock ensures Stop() cannot iterate srv.clients and
					// miss this connection, which would cause srv.wg.Wait() to hang.
					srv.mu.Lock()
					if srv.closing {
						// Stop() has already iterated srv.clients; close the
						// freshly dialled connection and exit the goroutine.
						srv.mu.Unlock()
						_ = client.Close()
						return
					}
					speaker.mu.Lock()
					speaker.lastAttempt = time.Now()
					speaker.isConnected = true
					speaker.retryDelay = 1 * time.Second // reset backoff on a successful connection
					speaker.mu.Unlock()
					srv.wg.Add(1)
					srv.clients[client] = struct{}{}
					srv.mu.Unlock()
					glog.V(5).Infof("client %s connected, calling bmpWorker", speaker.Address)
					go func() {
						defer srv.wg.Done()
						// Mark the speaker as disconnected when bmpWorker returns
						// so the connector loop will attempt to reconnect.
						defer func() {
							speaker.mu.Lock()
							speaker.isConnected = false
							speaker.mu.Unlock()
						}()
						defer func() {
							srv.mu.Lock()
							delete(srv.clients, client)
							srv.mu.Unlock()
						}()
						defer func() { _ = client.Close() }()
						// Hand the connection to bmpWorker — identical processing
						// pipeline as passive mode (parser → producer → publisher).
						srv.bmpWorker(client)
					}()
				} else {
					glog.Errorf("Failed to connect to BGP speaker %s: %v", speaker.Address, err)
					// Exponential backoff: double the retry delay on each failure,
					// capped at 5 minutes to avoid indefinitely long quiet periods.
					speaker.mu.Lock()
					speaker.lastAttempt = time.Now()
					newDelay := speaker.retryDelay * 2
					speaker.retryDelay = min(newDelay, 5*time.Minute)
					speaker.mu.Unlock()
					glog.Infof("Will retry connection to %s in %v", speaker.Address, speaker.retryDelay)
				}
			} else {
				speaker.mu.Unlock()
			}
		}
		// Sleep briefly between sweeps to avoid a busy-wait when all speakers
		// are either connected or still within their backoff window.
		select {
		case <-srv.connectorStopCh:
			glog.Infof("connector received stop signal, exiting")
			return
		case <-ticker.C:
		}
	}
}

// NewBMPServer instantiates a new instance of BMP Server
func NewBMPServer(cfg *config.Config) (BMPServer, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}
	if cfg.Publisher == nil {
		return nil, errors.New("publisher cannot be nil")
	}
	bmpSrv := bmpServer{
		isActive:    cfg.ActiveMode,
		clients:     make(map[net.Conn]struct{}),
		publisher:   cfg.Publisher,
		splitAF:     cfg.SplitAF == nil || *cfg.SplitAF, // nil means unset → default true
		bgpSpeakers: cfg.SpeakersList,
	}
	if !bmpSrv.isActive {
		incoming, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.BmpListenPort))
		if err != nil {
			glog.Errorf("fail to setup listener on port %d with error: %+v", cfg.BmpListenPort, err)
			return nil, err
		}
		bmpSrv.incoming = incoming
	}
	if bmpSrv.isActive && len(bmpSrv.bgpSpeakers) == 0 {
		return nil, errors.New("active_mode is true but speakers_list is empty")
	}
	if bmpSrv.isActive {
		if err := config.ValidateSpeakersList(bmpSrv.bgpSpeakers); err != nil {
			return nil, err
		}
		bmpSrv.connectorStopCh = make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		bmpSrv.connectorCtx = ctx
		bmpSrv.connectorCancel = cancel
	}
	if cfg.PublisherType == config.PublisherTypeKafka && cfg.KafkaConfig != nil {
		bmpSrv.bmpRaw = cfg.KafkaConfig.BmpRaw
		bmpSrv.adminID = cfg.KafkaConfig.AdminID
	}

	return &bmpSrv, nil
}
