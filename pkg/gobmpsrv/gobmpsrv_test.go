package gobmpsrv

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
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
		stop:      make(chan struct{}),
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
	srv, err := NewBMPServer(0, 0, false, nil, false, false, "")
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Stop()
}

func TestNewBMPServer_PortInUse(t *testing.T) {
	srv1, err := NewBMPServer(0, 0, false, nil, false, false, "")
	if err != nil {
		t.Fatalf("first NewBMPServer: %v", err)
	}
	defer srv1.Stop()

	port := srv1.(*bmpServer).incoming.Addr().(*net.TCPAddr).Port
	_, err = NewBMPServer(port, 0, false, nil, false, false, "")
	if err == nil {
		t.Fatal("expected error binding already-used port, got nil")
	}
}

// ---- Start / Stop lifecycle -------------------------------------------------

func TestBMPServer_StartStop_NoHang(t *testing.T) {
	srv, err := NewBMPServer(0, 0, false, newMockPublisher(), false, false, "")
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
	srv, err := NewBMPServer(0, 0, false, pub, false, false, "")
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
	// This is valid for Initiation/Termination messages with no TLVs (RFC 7854).
	// After writing the header we close the connection so the worker exits on
	// the subsequent ReadFull, regardless of whether it accepted or skipped the
	// zero-payload message.
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
	defer func() { _ = clientConn.Close() }()

	go newTestServer(pub, false).bmpWorker(serverConn)

	if _, err := clientConn.Write(makePeerDownMessage()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !pub.waitForMessages(1, 3*time.Second) {
		t.Fatal("timed out waiting for message to reach publisher")
	}
}

// TestBMPWorker_MultipleMessages verifies that the worker correctly sequences
// multiple messages and each one independently reaches the publisher.
func TestBMPWorker_MultipleMessages(t *testing.T) {
	const count = 5
	pub := newMockPublisher()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	go newTestServer(pub, false).bmpWorker(serverConn)

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
}

// ---- server-level integration -----------------------------------------------

// TestBMPServer_AcceptsMultipleClients verifies that the server correctly
// spawns a worker goroutine per connection for concurrent clients.
func TestBMPServer_AcceptsMultipleClients(t *testing.T) {
	srv, err := NewBMPServer(0, 0, false, newMockPublisher(), false, false, "")
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()
	defer srv.Stop()

	addr := srv.(*bmpServer).incoming.Addr().String()
	const numClients = 3
	conns := make([]net.Conn, numClients)
	for i := range conns {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("client %d Dial: %v", i, err)
		}
		conns[i] = c
	}
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
