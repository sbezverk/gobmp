package gobmpsrv

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/config"
)

// ---- test helpers -----------------------------------------------------------

// makePeerDownMessage returns a minimal, fully-valid 49-byte BMP PeerDown
// message suitable for end-to-end pipeline tests.
//
// Structure:
//   - Common Header (6 bytes):    version=3, length=49, type=PeerDownMsg
//   - Per-Peer Header (42 bytes): PeerType=0 (Global), all-zero flags /
//     address / AS / BGPID / timestamp — parses as an IPv4, AS-0 peer
//   - PeerDown body (1 byte):     reason=4 (remote system closed, no NOTIFICATION)
func makePeerDownMessage() []byte {
	totalLen := bmp.CommonHeaderLength + bmp.PerPeerHeaderLength + 1
	b := make([]byte, totalLen)
	b[0] = 3
	binary.BigEndian.PutUint32(b[1:5], uint32(totalLen))
	b[5] = bmp.PeerDownMsg
	// Per-Peer Header bytes [6:48] remain zero: PeerType0, IPv4, 0.0.0.0, AS 0.
	b[bmp.CommonHeaderLength+bmp.PerPeerHeaderLength] = 4 // PeerDown reason 4
	return b
}

// ---- mock publisher ---------------------------------------------------------

type mockPublisher struct {
	mu      sync.Mutex
	count   int
	ch      chan struct{}
	stopped bool
}

func newMockPublisher() *mockPublisher {
	return &mockPublisher{ch: make(chan struct{}, 64)}
}

func (m *mockPublisher) PublishMessage(_ int, _ []byte, _ []byte) error {
	m.mu.Lock()
	m.count++
	m.mu.Unlock()
	select {
	case m.ch <- struct{}{}:
	default:
	}
	return nil
}

func (m *mockPublisher) Stop() {
	m.mu.Lock()
	m.stopped = true
	m.mu.Unlock()
}

// waitForMessages blocks until n PublishMessage calls have been observed or
// the deadline d expires.
func (m *mockPublisher) waitForMessages(n int, d time.Duration) bool {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	received := 0
	for {
		select {
		case <-m.ch:
			received++
			if received >= n {
				return true
			}
		case <-deadline.C:
			return false
		}
	}
}

// ---- helpers for direct bmpWorker tests -------------------------------------

// newTestServer creates a minimal bmpServer for direct bmpWorker invocation.
// A listener is not required when calling bmpWorker directly.
func newTestServer(pub *mockPublisher, raw bool) *bmpServer {
	return &bmpServer{
		publisher: pub,
		bmpRaw:    raw,
	}
}

// workerDone starts bmpWorker in a goroutine and returns a channel that is
// closed when the function returns.
func workerDone(srv *bmpServer, conn net.Conn) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		srv.bmpWorker(conn)
		close(ch)
	}()
	return ch
}

// assertWorkerExits fails the test if bmpWorker has not returned within 2s.
func assertWorkerExits(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bmpWorker did not exit within 2s")
	}
}

// ---- NewBMPServer -----------------------------------------------------------

func TestNewBMPServer_Success(t *testing.T) {
	srv, err := NewBMPServer(&config.Config{Publisher: newMockPublisher()})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Stop()
}

func TestNewBMPServer_PortInUse(t *testing.T) {
	srv1, err := NewBMPServer(&config.Config{Publisher: newMockPublisher()})
	if err != nil {
		t.Fatalf("first NewBMPServer: %v", err)
	}
	defer srv1.Stop()

	port := srv1.(*bmpServer).incoming.Addr().(*net.TCPAddr).Port
	_, err = NewBMPServer(&config.Config{Publisher: newMockPublisher(), BmpListenPort: port})
	if err == nil {
		t.Fatal("expected error binding already-used port, got nil")
	}
}

// ---- Start / Stop lifecycle -------------------------------------------------

func TestBMPServer_StartStop_NoHang(t *testing.T) {
	srv, err := NewBMPServer(&config.Config{Publisher: newMockPublisher()})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()

	done := make(chan struct{})
	go func() {
		srv.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2s — possible goroutine leak")
	}
}

func TestBMPServer_Stop_CallsPublisherStop(t *testing.T) {
	pub := newMockPublisher()
	srv, err := NewBMPServer(&config.Config{Publisher: pub})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Stop()

	pub.mu.Lock()
	defer pub.mu.Unlock()
	if !pub.stopped {
		t.Error("expected publisher.Stop() to be called by srv.Stop()")
	}
}

// ---- bmpWorker: error / connection-close paths ------------------------------

func TestBMPWorker_ImmediateEOF(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	_ = clientConn.Close() // triggers EOF on the server side immediately

	assertWorkerExits(t, workerDone(newTestServer(nil, false), serverConn))
}

func TestBMPWorker_BadHeaderVersion(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	// Version byte must be 3; send 1 to trigger an unmarshal error.
	hdr := make([]byte, bmp.CommonHeaderLength)
	hdr[0] = 1
	binary.BigEndian.PutUint32(hdr[1:5], uint32(bmp.CommonHeaderLength+10))
	hdr[5] = bmp.TerminationMsg

	done := workerDone(newTestServer(nil, false), serverConn)
	if _, err := clientConn.Write(hdr); err != nil {
		t.Fatalf("Write: %v", err)
	}
	assertWorkerExits(t, done)
}

func TestBMPWorker_InvalidMsgLen_Negative(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	// MessageLength < CommonHeaderLength is structurally impossible — reject immediately.
	hdr := make([]byte, bmp.CommonHeaderLength)
	hdr[0] = 3
	binary.BigEndian.PutUint32(hdr[1:5], uint32(bmp.CommonHeaderLength-1))
	hdr[5] = bmp.TerminationMsg

	done := workerDone(newTestServer(nil, false), serverConn)
	if _, err := clientConn.Write(hdr); err != nil {
		t.Fatalf("Write: %v", err)
	}
	assertWorkerExits(t, done)
}

func TestBMPWorker_ZeroPayload_GracefulExit(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	// MessageLength == CommonHeaderLength means zero-byte payload.
	// Valid for Initiation/Termination (RFC 7854 §4.3/§4.5 allow an empty TLV section).
	// After writing the header we close the connection so the worker exits on
	// the subsequent ReadFull.
	hdr := make([]byte, bmp.CommonHeaderLength)
	hdr[0] = 3
	binary.BigEndian.PutUint32(hdr[1:5], uint32(bmp.CommonHeaderLength))
	hdr[5] = bmp.TerminationMsg

	done := workerDone(newTestServer(nil, false), serverConn)
	if _, err := clientConn.Write(hdr); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = clientConn.Close() // triggers EOF on the next header read
	assertWorkerExits(t, done)
}

func TestBMPWorker_ZeroPayload_NonTLVType_Rejected(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	// PeerDown requires at least a Per-Peer Header; zero payload is malformed
	// and must cause the server to close the connection immediately.
	hdr := make([]byte, bmp.CommonHeaderLength)
	hdr[0] = 3
	binary.BigEndian.PutUint32(hdr[1:5], uint32(bmp.CommonHeaderLength))
	hdr[5] = bmp.PeerDownMsg

	done := workerDone(newTestServer(nil, false), serverConn)
	if _, err := clientConn.Write(hdr); err != nil {
		t.Fatalf("Write: %v", err)
	}
	assertWorkerExits(t, done)
}

func TestBMPWorker_InvalidMsgLen_TooLarge(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	// Declare a payload one byte over the 1 MB limit.
	hdr := make([]byte, bmp.CommonHeaderLength)
	hdr[0] = 3
	binary.BigEndian.PutUint32(hdr[1:5], uint32(bmp.CommonHeaderLength+(1<<20)+1))
	hdr[5] = bmp.TerminationMsg

	done := workerDone(newTestServer(nil, false), serverConn)
	if _, err := clientConn.Write(hdr); err != nil {
		t.Fatalf("Write: %v", err)
	}
	assertWorkerExits(t, done)
}

func TestBMPWorker_InvalidMsgLen_MaxUint32(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	hdr := make([]byte, bmp.CommonHeaderLength)
	hdr[0] = 3
	binary.BigEndian.PutUint32(hdr[1:5], ^uint32(0)) // 0xFFFFFFFF
	hdr[5] = bmp.TerminationMsg

	done := workerDone(newTestServer(nil, false), serverConn)
	if _, err := clientConn.Write(hdr); err != nil {
		t.Fatalf("Write: %v", err)
	}
	assertWorkerExits(t, done)
}

func TestBMPWorker_TruncatedPayload(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	// Header declares 50 bytes of payload; we only deliver 10 then close.
	hdr := make([]byte, bmp.CommonHeaderLength)
	hdr[0] = 3
	binary.BigEndian.PutUint32(hdr[1:5], uint32(bmp.CommonHeaderLength+50))
	hdr[5] = bmp.TerminationMsg

	done := workerDone(newTestServer(nil, false), serverConn)
	if _, err := clientConn.Write(hdr); err != nil {
		t.Fatalf("Write header: %v", err)
	}
	if _, err := clientConn.Write(make([]byte, 10)); err != nil {
		t.Fatalf("Write partial payload: %v", err)
	}
	_ = clientConn.Close() // EOF mid-payload
	assertWorkerExits(t, done)
}

// ---- bmpWorker: valid message / publisher integration -----------------------

// TestBMPWorker_ValidMessage_ReachesPublisher sends a fully-valid BMP PeerDown
// message through the complete pipeline (bmpWorker → parser → producer →
// publisher) and asserts that PublishMessage is invoked.
//
// Message anatomy:
//   - Common Header  (6 bytes):  version=3, length=49, type=2 (PeerDown)
//   - Per-Peer Header (42 bytes): PeerType0, IPv4, all-zero address / AS / BGPID
//   - PeerDown body   (1 byte):  reason=4 (remote closed, no NOTIFICATION)
func TestBMPWorker_ValidMessage_ReachesPublisher(t *testing.T) {
	pub := newMockPublisher()
	serverConn, clientConn := net.Pipe()

	done := workerDone(newTestServer(pub, false), serverConn)

	if _, err := clientConn.Write(makePeerDownMessage()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !pub.waitForMessages(1, 3*time.Second) {
		t.Fatal("timed out waiting for message to reach publisher")
	}
	_ = clientConn.Close()
	assertWorkerExits(t, done)
}

// TestBMPWorker_MultipleMessages verifies that the worker correctly sequences
// multiple messages and each one independently reaches the publisher.
func TestBMPWorker_MultipleMessages(t *testing.T) {
	const count = 5
	pub := newMockPublisher()
	serverConn, clientConn := net.Pipe()

	done := workerDone(newTestServer(pub, false), serverConn)

	msg := makePeerDownMessage()
	for i := 0; i < count; i++ {
		if _, err := clientConn.Write(msg); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	if !pub.waitForMessages(count, 5*time.Second) {
		pub.mu.Lock()
		got := pub.count
		pub.mu.Unlock()
		t.Fatalf("expected %d published messages, got %d", count, got)
	}
	_ = clientConn.Close()
	assertWorkerExits(t, done)
}

// ---- server-level integration -----------------------------------------------

// TestBMPServer_AcceptsMultipleClients verifies that the server correctly
// spawns a worker goroutine per connection for concurrent clients and that
// all worker goroutines exit cleanly once their connections are closed.
// srv.Stop() calls wg.Wait() internally, so a test-wide timeout on Stop()
// is the implicit assertion that no workers leaked.
func TestBMPServer_AcceptsMultipleClients(t *testing.T) {
	srv, err := NewBMPServer(&config.Config{Publisher: newMockPublisher()})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()

	port := srv.(*bmpServer).incoming.Addr().(*net.TCPAddr).Port
	addr := "127.0.0.1:" + strconv.Itoa(port)
	const numClients = 3
	conns := make([]net.Conn, numClients)
	for i := range conns {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("client %d Dial: %v", i, err)
		}
		conns[i] = c
	}

	// Stop() closes the listener, then closes every active client connection
	// (unblocking io.ReadFull in each worker), then calls wg.Wait().
	// We do NOT close the conns manually here — the test exercises that Stop()
	// itself drives all workers to exit even on long-lived connections.
	stopped := make(chan struct{})
	go func() {
		srv.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2s — goroutines from bmpWorker may have leaked")
	}

	// Drain any connections the server already closed; ignore errors.
	for _, c := range conns {
		_ = c.Close()
	}
}

// ---- message length boundary coverage ---------------------------------------

func TestBMPWorker_MsgLen_ExactlyAtLimit(t *testing.T) {
	// A message with payload == 1MB (the maximum allowed) must NOT be rejected.
	// Write only the header so the worker blocks on ReadFull for the body.
	// Then close the connection to trigger a truncation error (not a limit error).
	serverConn, clientConn := net.Pipe()

	hdr := make([]byte, bmp.CommonHeaderLength)
	hdr[0] = 3
	binary.BigEndian.PutUint32(hdr[1:5], uint32(bmp.CommonHeaderLength+(1<<20)))
	hdr[5] = bmp.TerminationMsg

	done := workerDone(newTestServer(nil, false), serverConn)
	if _, err := clientConn.Write(hdr); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Close without sending body — worker should exit due to truncation, not length rejection.
	_ = clientConn.Close()
	assertWorkerExits(t, done)
}

// ---- additional mock helpers ------------------------------------------------

// mockAddr is a configurable net.Addr that returns a fixed string.
// Used to supply non-TCPAddr remote addresses to bmpWorker so that the
// speakerIP extraction fallback code paths are exercised.
type mockAddr struct{ addr string }

func (a mockAddr) Network() string { return "mock" }
func (a mockAddr) String() string  { return a.addr }

// mockConnWithAddr wraps a net.Conn and overrides RemoteAddr.
type mockConnWithAddr struct {
	net.Conn
	remote net.Addr
}

func (c *mockConnWithAddr) RemoteAddr() net.Addr { return c.remote }

// wrapAddr returns conn with its RemoteAddr overridden to the given address
// string. The underlying connection (Read/Write/Close) is unchanged.
func wrapAddr(conn net.Conn, addr string) *mockConnWithAddr {
	return &mockConnWithAddr{Conn: conn, remote: mockAddr{addr}}
}

// immediateReadErrorConn wraps a net.Conn but always returns net.ErrInvalid
// on the first Read call. This exercises the non-clean header-read error path
// in bmpWorker (i.e. the glog.Errorf branch that is skipped for EOF /
// net.ErrClosed / io.ErrUnexpectedEOF).
type immediateReadErrorConn struct {
	net.Conn
}

func (c *immediateReadErrorConn) Read([]byte) (int, error) {
	return 0, errors.New("transport error") // not EOF, not net.ErrClosed
}
func (c *immediateReadErrorConn) RemoteAddr() net.Addr { return mockAddr{"192.0.2.1:5000"} }

// mockListener delivers a pre-configured sequence of errors from Accept(),
// then blocks until Close() is called (returning net.ErrClosed). A ready
// channel is closed once the first error has been delivered, allowing tests
// to synchronise before calling Stop().
type mockListener struct {
	addr      mockAddr
	mu        sync.Mutex
	pending   []error
	readyOnce sync.Once
	ready     chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func newMockListener(errs ...error) *mockListener {
	return &mockListener{
		addr:    mockAddr{"0.0.0.0:0"},
		pending: errs,
		ready:   make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (l *mockListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.pending) > 0 {
		err := l.pending[0]
		l.pending = l.pending[1:]
		l.mu.Unlock()
		l.readyOnce.Do(func() { close(l.ready) })
		return nil, err
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *mockListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *mockListener) Addr() net.Addr { return l.addr }

// ---- NewBMPServer: nil-config, nil-publisher, and Kafka-config paths --------

func TestNewBMPServer_NilConfig(t *testing.T) {
	_, err := NewBMPServer(nil)
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

func TestNewBMPServer_NilPublisher(t *testing.T) {
	_, err := NewBMPServer(&config.Config{})
	if err == nil {
		t.Fatal("expected error for nil publisher, got nil")
	}
}

func TestNewBMPServer_KafkaConfig_SetsRawAndAdminID(t *testing.T) {
	cfg := &config.Config{
		Publisher:     newMockPublisher(),
		PublisherType: config.PublisherTypeKafka,
		KafkaConfig: &config.KafkaConfig{
			BmpRaw:  true,
			AdminID: "test-collector",
		},
	}
	srv, err := NewBMPServer(cfg)
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	bs := srv.(*bmpServer)
	if !bs.bmpRaw {
		t.Error("bmpRaw = false, want true")
	}
	if bs.adminID != "test-collector" {
		t.Errorf("adminID = %q, want test-collector", bs.adminID)
	}
	srv.Stop()
}

// ---- startWorker: closing-state race path -----------------------------------

// TestStartWorker_WhenClosing_ClosesConnection verifies that startWorker
// immediately closes the connection (without enqueuing a goroutine) when
// srv.closing is already true — the race-safe shutdown path.
func TestStartWorker_WhenClosing_ClosesConnection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	srv := &bmpServer{
		clients:   make(map[net.Conn]struct{}),
		publisher: newMockPublisher(),
	}
	srv.closing = true // pre-set as Stop() would have done
	srv.startWorker(serverConn)

	// serverConn must be closed by startWorker; reading from clientConn returns an error.
	_ = clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := clientConn.Read(buf)
	if err == nil {
		t.Error("expected read error after serverConn was closed, got nil")
	}
}

// ---- server(): non-net.ErrClosed accept error continues the loop ------------

// TestBMPServer_Accept_NonErrClosed_ContinuesLoop verifies that a transient
// Accept() error that is NOT net.ErrClosed causes server() to log an error
// and continue the accept loop rather than exiting.
func TestBMPServer_Accept_NonErrClosed_ContinuesLoop(t *testing.T) {
	ml := newMockListener(errors.New("transient accept error")) // one transient error, then blocks on Close
	srv := &bmpServer{
		clients:   make(map[net.Conn]struct{}),
		publisher: newMockPublisher(),
		incoming:  ml,
	}
	srv.Start()
	// Wait until the error has been delivered (and logged by server()).
	select {
	case <-ml.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("transient accept error was not delivered within 2s")
	}
	srv.Stop()
}

// ---- bmpWorker: alternative speakerIP extraction paths ---------------------

// TestBMPWorker_SpeakerIP_BareIP exercises the path where RemoteAddr() returns
// a bare IP string (no port). SplitHostPort fails; ParseIP succeeds.
func TestBMPWorker_SpeakerIP_BareIP(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	wrapped := wrapAddr(serverConn, "192.0.2.1")

	done := workerDone(newTestServer(newMockPublisher(), false), wrapped)
	_ = clientConn.Close() // immediate EOF → worker exits cleanly
	assertWorkerExits(t, done)
}

// TestBMPWorker_SpeakerIP_HostPort exercises the path where RemoteAddr()
// returns a "host:port" string (not *net.TCPAddr). SplitHostPort succeeds,
// no zone ID, ParseIP succeeds.
func TestBMPWorker_SpeakerIP_HostPort(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	wrapped := wrapAddr(serverConn, "192.0.2.1:5000")

	done := workerDone(newTestServer(newMockPublisher(), false), wrapped)
	_ = clientConn.Close()
	assertWorkerExits(t, done)
}

// TestBMPWorker_SpeakerIP_HostPortWithZone exercises the IPv6 zone-ID
// stripping path: "[fe80::1%eth0]:5000" → host = "fe80::1%eth0" → zone
// stripped via strings.Cut → ParseIP("fe80::1") succeeds.
func TestBMPWorker_SpeakerIP_HostPortWithZone(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	wrapped := wrapAddr(serverConn, "[fe80::1%eth0]:5000")

	done := workerDone(newTestServer(newMockPublisher(), false), wrapped)
	_ = clientConn.Close()
	assertWorkerExits(t, done)
}

// TestBMPWorker_HeaderRead_NonCleanError exercises the glog.Errorf branch
// reached when the header ReadFull returns a non-clean error (not EOF,
// net.ErrClosed, or io.ErrUnexpectedEOF).
func TestBMPWorker_HeaderRead_NonCleanError(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	conn := &immediateReadErrorConn{Conn: serverConn}

	done := workerDone(newTestServer(newMockPublisher(), false), conn)
	assertWorkerExits(t, done)
}
