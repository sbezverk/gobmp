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

// immediateReadErrorConn wraps a net.Conn but always returns a non-nil,
// non-clean error on every Read call. This exercises the glog.Errorf branch
// in bmpWorker that is skipped for the clean-close errors (io.EOF,
// net.ErrClosed, io.ErrUnexpectedEOF).
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

// ---- active mode helpers ----------------------------------------------------

// freeAddr briefly binds a random TCP port and immediately releases it,
// returning the "host:port" string. The caller receives an address that was
// recently valid (so it passes format validation in NewBMPServer) but is no
// longer listening, causing DialContext to fail with ECONNREFUSED.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr Listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// acceptWithTimeout blocks until ln.Accept() succeeds or d elapses.
// On timeout it returns nil and a descriptive error without closing ln.
func acceptWithTimeout(t *testing.T, ln net.Listener, d time.Duration) net.Conn {
	t.Helper()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Accept: %v", r.err)
		}
		return r.c
	case <-time.After(d):
		t.Fatalf("timed out waiting for connection after %v", d)
		return nil
	}
}

// stopWithTimeout calls srv.Stop() in a goroutine and fails the test if it has
// not returned within d.
func stopWithTimeout(t *testing.T, srv BMPServer, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		srv.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("Stop() did not return within %v — possible goroutine leak", d)
	}
}

// ---- NewBMPServer: active mode construction ---------------------------------

func TestNewBMPServer_ActiveMode_EmptySpeakers(t *testing.T) {
	_, err := NewBMPServer(&config.Config{
		Publisher:  newMockPublisher(),
		ActiveMode: true,
	})
	if err == nil {
		t.Fatal("expected error for active_mode=true with empty speakers_list, got nil")
	}
}

func TestNewBMPServer_ActiveMode_InvalidAddress(t *testing.T) {
	_, err := NewBMPServer(&config.Config{
		Publisher:    newMockPublisher(),
		ActiveMode:   true,
		SpeakersList: []string{"not-a-valid-address"},
	})
	if err == nil {
		t.Fatal("expected error for invalid speaker address, got nil")
	}
}

func TestNewBMPServer_ActiveMode_HostnameRejected(t *testing.T) {
	// speakers_list only accepts IP literals; hostnames must be rejected.
	_, err := NewBMPServer(&config.Config{
		Publisher:    newMockPublisher(),
		ActiveMode:   true,
		SpeakersList: []string{"router.example.com:5000"},
	})
	if err == nil {
		t.Fatal("expected error for hostname speaker address, got nil")
	}
}

func TestNewBMPServer_ActiveMode_InvalidPort(t *testing.T) {
	_, err := NewBMPServer(&config.Config{
		Publisher:    newMockPublisher(),
		ActiveMode:   true,
		SpeakersList: []string{"127.0.0.1:99999"},
	})
	if err == nil {
		t.Fatal("expected error for out-of-range speaker port, got nil")
	}
}

func TestNewBMPServer_ActiveMode_DuplicateSpeaker(t *testing.T) {
	_, err := NewBMPServer(&config.Config{
		Publisher:    newMockPublisher(),
		ActiveMode:   true,
		SpeakersList: []string{"127.0.0.1:5000", "127.0.0.1:5000"},
	})
	if err == nil {
		t.Fatal("expected error for duplicate speaker address, got nil")
	}
}

func TestNewBMPServer_ActiveMode_Success_ChecksFields(t *testing.T) {
	srv, err := NewBMPServer(&config.Config{
		Publisher:    newMockPublisher(),
		ActiveMode:   true,
		SpeakersList: []string{"127.0.0.1:5000"},
	})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	bs := srv.(*bmpServer)
	if !bs.isActive {
		t.Error("isActive = false, want true")
	}
	if bs.connectorStopCh == nil {
		t.Error("connectorStopCh is nil, want initialised channel")
	}
	if bs.connectorCancel == nil {
		t.Error("connectorCancel is nil, want non-nil cancel func")
	}
	if bs.incoming != nil {
		t.Error("incoming listener should be nil in active mode")
	}
	if len(bs.bgpSpeakers) != 1 || bs.bgpSpeakers[0] != "127.0.0.1:5000" {
		t.Errorf("bgpSpeakers = %v, want [127.0.0.1:5000]", bs.bgpSpeakers)
	}
	stopWithTimeout(t, srv, 3*time.Second)
}

// ---- Start / Stop lifecycle (active mode) -----------------------------------

func TestBMPServer_ActiveMode_StartStop_NoHang(t *testing.T) {
	// The address is not listening; connector fails with ECONNREFUSED immediately
	// and enters backoff. Stop() cancels the wait via connectorStopCh promptly.
	srv, err := NewBMPServer(&config.Config{
		Publisher:    newMockPublisher(),
		ActiveMode:   true,
		SpeakersList: []string{freeAddr(t)},
	})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()
	stopWithTimeout(t, srv, 3*time.Second)
}

func TestBMPServer_ActiveMode_Stop_CallsPublisherStop(t *testing.T) {
	pub := newMockPublisher()
	srv, err := NewBMPServer(&config.Config{
		Publisher:    pub,
		ActiveMode:   true,
		SpeakersList: []string{freeAddr(t)},
	})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()
	stopWithTimeout(t, srv, 3*time.Second)

	pub.mu.Lock()
	defer pub.mu.Unlock()
	if !pub.stopped {
		t.Error("expected publisher.Stop() to be called by srv.Stop() in active mode")
	}
}

// ---- Active mode: connector happy paths -------------------------------------

// TestBMPServer_ActiveMode_ConnectsAndProcessesBMP starts a local TCP listener
// that simulates a BGP speaker. The active-mode gobmp server dials out, the
// "speaker" writes a valid BMP frame, and the test verifies it reaches the publisher.
func TestBMPServer_ActiveMode_ConnectsAndProcessesBMP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	pub := newMockPublisher()
	srv, err := NewBMPServer(&config.Config{
		Publisher:    pub,
		ActiveMode:   true,
		SpeakersList: []string{ln.Addr().String()},
	})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()

	// gobmp is the dialer in active mode; accept that outbound connection here.
	speakerConn := acceptWithTimeout(t, ln, 5*time.Second)
	defer speakerConn.Close()

	if _, err := speakerConn.Write(makePeerDownMessage()); err != nil {
		srv.Stop()
		t.Fatalf("Write BMP message: %v", err)
	}
	if !pub.waitForMessages(1, 5*time.Second) {
		srv.Stop()
		t.Fatal("timed out waiting for BMP message to reach publisher")
	}
	stopWithTimeout(t, srv, 3*time.Second)
}

// TestBMPServer_ActiveMode_MultipleSpeakers verifies that gobmp in active mode
// connects to all configured speakers concurrently and publishes a message from each.
func TestBMPServer_ActiveMode_MultipleSpeakers(t *testing.T) {
	const n = 3
	listeners := make([]net.Listener, n)
	addrs := make([]string, n)
	for i := range listeners {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen[%d]: %v", i, err)
		}
		defer ln.Close()
		listeners[i] = ln
		addrs[i] = ln.Addr().String()
	}

	pub := newMockPublisher()
	srv, err := NewBMPServer(&config.Config{
		Publisher:    pub,
		ActiveMode:   true,
		SpeakersList: addrs,
	})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()

	msg := makePeerDownMessage()
	speakerConns := make([]net.Conn, n)
	for i, ln := range listeners {
		c := acceptWithTimeout(t, ln, 5*time.Second)
		speakerConns[i] = c
		if _, err := c.Write(msg); err != nil {
			srv.Stop()
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	defer func() {
		for _, c := range speakerConns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()

	if !pub.waitForMessages(n, 10*time.Second) {
		pub.mu.Lock()
		got := pub.count
		pub.mu.Unlock()
		srv.Stop()
		t.Fatalf("expected %d published messages, got %d", n, got)
	}
	stopWithTimeout(t, srv, 3*time.Second)
}

// TestBMPServer_ActiveMode_ReconnectsAfterDisconnect verifies that after the
// speaker closes the connection, the connector marks the speaker as disconnected
// and re-dials once the retry delay (reset to 1 s on a successful connection) elapses.
func TestBMPServer_ActiveMode_ReconnectsAfterDisconnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	srv, err := NewBMPServer(&config.Config{
		Publisher:    newMockPublisher(),
		ActiveMode:   true,
		SpeakersList: []string{ln.Addr().String()},
	})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()

	// Accept and immediately close: simulates a speaker that drops the session.
	conn1 := acceptWithTimeout(t, ln, 5*time.Second)
	_ = conn1.Close()

	// The connector resets retryDelay to 1 s on a successful connection.
	// After bmpWorker exits it marks isConnected=false; the retry fires ≈1 s
	// after the initial dial. Allow 4 s for the second connection.
	conn2 := acceptWithTimeout(t, ln, 4*time.Second)
	_ = conn2.Close()

	stopWithTimeout(t, srv, 3*time.Second)
}

// TestBMPServer_ActiveMode_StopInterruptsDial verifies that Stop() cancels the
// connector's backoff wait promptly even when all speakers are unreachable.
func TestBMPServer_ActiveMode_StopInterruptsDial(t *testing.T) {
	// freeAddr gives a recently-valid address that is now ECONNREFUSED, so the
	// first dial fails quickly and the connector enters its backoff. Stop() must
	// interrupt that wait rather than block until the timer expires.
	srv, err := NewBMPServer(&config.Config{
		Publisher:    newMockPublisher(),
		ActiveMode:   true,
		SpeakersList: []string{freeAddr(t)},
	})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()
	// One full sweep (200 ms tick) ensures the connector has attempted its first
	// dial and is now sleeping in the ticker select.
	time.Sleep(300 * time.Millisecond)
	stopWithTimeout(t, srv, 3*time.Second)
}

// TestBMPServer_ActiveMode_ClosingRaceWithDial exercises the srv.closing guard
// inside connector(): if Stop() sets closing=true just after a successful dial,
// the connector must close the connection and exit rather than spawning a
// bmpWorker goroutine. Both outcomes must leave Stop() unblocked.
func TestBMPServer_ActiveMode_ClosingRaceWithDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	srv, err := NewBMPServer(&config.Config{
		Publisher:    newMockPublisher(),
		ActiveMode:   true,
		SpeakersList: []string{ln.Addr().String()},
	})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()

	// Drain accepted connections so the listener does not stall gobmp's dial.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Race Stop() against the in-flight dial; either path must not hang.
	time.Sleep(50 * time.Millisecond)
	stopWithTimeout(t, srv, 3*time.Second)
}
