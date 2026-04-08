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

// maxConnections is the default upper bound on concurrent BMP sessions.
const maxConnections = 1024

// readTimeout is the deadline for each io.ReadFull call on a BMP connection.
// A peer that sends no data for this duration is disconnected.
const readTimeout = 5 * time.Minute

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
	wg        sync.WaitGroup // tracks server()/connectSpeaker() + in-flight bmpWorker goroutines
	mu        sync.Mutex     // protects clients and closing
	stopOnce  sync.Once
	clients   map[net.Conn]struct{} // active bmpWorker connections
	closing   bool                  // set to true in Stop() before iterating clients
	connSem   chan struct{}         // semaphore limiting concurrent connections
	bmpRaw    bool
	adminID   string
	// Active-mode fields — all nil/zero in passive mode.
	connectorStopCh chan struct{}      // closed by stopConnector() to signal connector() to exit
	bgpSpeakers     []string           // list of "host:port" addresses to dial
	connectorCtx    context.Context    // parent context for all dials; cancelled by stopConnector()
	connectorCancel context.CancelFunc // cancels connectorCtx
}

func (srv *bmpServer) Start() {
	if srv.isActive {
		glog.Infof("Starting gobmp server in Active mode")
		// Spawn all per-speaker goroutines under srv.mu so that every wg.Add
		// completes before Stop() can acquire the lock, set srv.closing, and
		// reach wg.Wait().  sync.WaitGroup forbids Add(+1) concurrent with
		// Wait(), so we must guarantee all adds are visible before Wait is
		// called.  Holding srv.mu here and checking srv.closing in Stop()
		// before wg.Wait() provides that guarantee without a connector()
		// goroutine.
		srv.mu.Lock()
		for _, addr := range srv.bgpSpeakers {
			speaker := &bgpSpeaker{Address: addr, retryDelay: 1 * time.Second}
			srv.wg.Add(1)
			go srv.connectSpeaker(speaker)
		}
		srv.mu.Unlock()
	} else {
		glog.Infof("Starting gobmp server on %s", srv.incoming.Addr().String())
		srv.wg.Add(1)
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
		// Enforce connection limit — reject if at capacity.
		select {
		case srv.connSem <- struct{}{}:
		default:
			glog.Warningf("connection limit reached (%d), rejecting %v", maxConnections, client.RemoteAddr())
			client.Close()
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
			// Release connection semaphore slot (passive mode only).
			if srv.connSem != nil {
				<-srv.connSem
			}
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
		// Set read deadline to detect idle/malicious connections.
		_ = client.SetReadDeadline(time.Now().Add(readTimeout))
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
		_ = client.SetReadDeadline(time.Now().Add(readTimeout))
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
	nextAttempt time.Time     // earliest time for the next dial attempt (zero = immediate)
	retryDelay  time.Duration // current backoff delay; doubles on each failure up to 5 minutes
}

// stopConnector signals all per-speaker goroutines to exit and cancels any
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

// connectSpeaker manages the full lifecycle (dial → bmpWorker → backoff →
// redial) for a single BGP speaker.  It runs as its own goroutine so that
// a blocked or slow dial cannot stall connection attempts to other speakers.
func (srv *bmpServer) connectSpeaker(speaker *bgpSpeaker) {
	defer srv.wg.Done()
	for {
		// Honour a stop signal before each dial attempt.
		select {
		case <-srv.connectorStopCh:
			glog.Infof("connectSpeaker(%s): stop signal received, exiting", speaker.Address)
			return
		default:
		}

		// Wait out the current backoff delay, but wake immediately on stop.
		// nextAttempt is set after each dial attempt (success or failure) so the
		// wait is measured from when the dial *returned*, not when it started.
		speaker.mu.Lock()
		remaining := time.Until(speaker.nextAttempt)
		speaker.mu.Unlock()
		if remaining > 0 {
			select {
			case <-srv.connectorStopCh:
				glog.Infof("connectSpeaker(%s): stop signal received during backoff, exiting", speaker.Address)
				return
			case <-time.After(remaining):
			}
		}

		glog.Infof("Attempting to connect to BGP speaker %s", speaker.Address)

		// Derive a timeout context from connectorCtx so that
		// stopConnector() (which cancels connectorCtx) also aborts
		// any dial that is currently in progress.
		ctx, cancel := context.WithTimeout(srv.connectorCtx, 5*time.Second)
		client, err := (&net.Dialer{}).DialContext(ctx, "tcp", speaker.Address)
		cancel() // always release the timer goroutine regardless of outcome

		if err != nil {
			// context.Canceled means stopConnector() cancelled connectorCtx while
			// the dial was in progress — this is a clean shutdown, not a network
			// error.  Exit immediately without error logging or backoff so that
			// Stop() completes quietly.  net.ErrClosed can surface for the same
			// reason on some platforms (underlying fd closed under the dialer).
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				glog.Infof("connectSpeaker(%s): dial cancelled during shutdown, exiting", speaker.Address)
				return
			}
			glog.Errorf("Failed to connect to BGP speaker %s: %v", speaker.Address, err)
			// Exponential backoff: double the retry delay on each failure,
			// capped at 5 minutes to avoid indefinitely long quiet periods.
			// nextAttempt is set here — after DialContext returned — so the full
			// backoff window is preserved even when the dial blocked for its
			// entire 5-second timeout.
			speaker.mu.Lock()
			newDelay := speaker.retryDelay * 2
			speaker.retryDelay = min(newDelay, 5*time.Minute)
			speaker.nextAttempt = time.Now().Add(speaker.retryDelay)
			speaker.mu.Unlock()
			glog.Infof("Will retry connection to %s in %v", speaker.Address, speaker.retryDelay)
			continue
		}

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
		speaker.isConnected = true
		speaker.retryDelay = 1 * time.Second // reset backoff on a successful connection
		speaker.nextAttempt = time.Time{}    // allow immediate reconnect after a clean disconnect
		speaker.mu.Unlock()
		srv.wg.Add(1)
		srv.clients[client] = struct{}{}
		srv.mu.Unlock()

		glog.V(5).Infof("client %s connected, calling bmpWorker", speaker.Address)
		// Run bmpWorker synchronously: this goroutine is dedicated to this
		// speaker, so blocking here is correct and avoids an extra goroutine.
		func() {
			defer srv.wg.Done()
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
			srv.bmpWorker(client)
		}()
		// bmpWorker returned — the connection dropped; schedule reconnect with backoff.
		speaker.mu.Lock()
		speaker.nextAttempt = time.Now().Add(speaker.retryDelay)
		speaker.mu.Unlock()
		glog.Infof("connectSpeaker(%s): bmpWorker exited, scheduling reconnect in %v", speaker.Address, speaker.retryDelay)
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
		bmpSrv.connSem = make(chan struct{}, maxConnections)
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
