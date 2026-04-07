package message

import (
	"crypto/md5"
	"fmt"
	"testing"
)

// TestTransportIPSetAtConstruction verifies that transport_ip/transport_hash are
// set once at construction time via SetConfig and remain immutable.
func TestTransportIPSetAtConstruction(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	transportIP := "192.0.2.1"
	if err := p.SetConfig(&Config{TransportIP: transportIP}); err != nil {
		t.Fatalf("SetConfig() error: %v", err)
	}

	if p.transportIP != transportIP {
		t.Errorf("transportIP = %v, want %v", p.transportIP, transportIP)
	}
	wantHash := fmt.Sprintf("%x", md5.Sum([]byte(transportIP)))
	if p.transportHash != wantHash {
		t.Errorf("transportHash = %v, want %v", p.transportHash, wantHash)
	}
}

// TestPeerLocalPerTable verifies that router_ip/router_hash (BGP local address) are
// stored and retrieved per-peer, so multiple BGP peers on a single BMP session
// each return their own local peering address.
func TestPeerLocalPerTable(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	peer1Key := "10.0.0.10:0"
	peer1LocalIP := "192.0.2.10"

	peer2Key := "10.0.0.11:65000:100"
	peer2LocalIP := "172.16.0.1"

	p.tableLock.Lock()
	p.tableProperties[peer1Key] = PerTableProperties{
		addPathCapable: make(map[int]bool),
		localIP:        peer1LocalIP,
		localHash:      fmt.Sprintf("%x", md5.Sum([]byte(peer1LocalIP))),
	}
	p.tableProperties[peer2Key] = PerTableProperties{
		addPathCapable: make(map[int]bool),
		localIP:        peer2LocalIP,
		localHash:      fmt.Sprintf("%x", md5.Sum([]byte(peer2LocalIP))),
	}
	p.tableLock.Unlock()

	got1IP, got1Hash := p.peerLocal(peer1Key)
	if got1IP != peer1LocalIP {
		t.Errorf("peer1 localIP = %v, want %v", got1IP, peer1LocalIP)
	}
	want1Hash := fmt.Sprintf("%x", md5.Sum([]byte(peer1LocalIP)))
	if got1Hash != want1Hash {
		t.Errorf("peer1 localHash = %v, want %v", got1Hash, want1Hash)
	}

	got2IP, got2Hash := p.peerLocal(peer2Key)
	if got2IP != peer2LocalIP {
		t.Errorf("peer2 localIP = %v, want %v", got2IP, peer2LocalIP)
	}
	want2Hash := fmt.Sprintf("%x", md5.Sum([]byte(peer2LocalIP)))
	if got2Hash != want2Hash {
		t.Errorf("peer2 localHash = %v, want %v", got2Hash, want2Hash)
	}

	// Verify peers are independent
	if got1IP == got2IP {
		t.Errorf("peer1 and peer2 should have different local IPs, both got %v", got1IP)
	}
}

// TestPeerLocalUnknownTable verifies that peerLocal returns empty strings when
// no PeerUp has been received for the given table key.
func TestPeerLocalUnknownTable(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	localIP, localHash := p.peerLocal("nonexistent-table-key")
	if localIP != "" {
		t.Errorf("expected empty localIP for unknown table, got %q", localIP)
	}
	if localHash != "" {
		t.Errorf("expected empty localHash for unknown table, got %q", localHash)
	}
}

// TestPeerLocalClearedOnPeerDown verifies that local_ip/local_hash are no longer
// available after the table entry is removed (simulating PeerDown cleanup).
func TestPeerLocalClearedOnPeerDown(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	tableKey := "10.0.0.10:0"
	localIP := "192.0.2.10"

	// Simulate PeerUp
	p.tableLock.Lock()
	p.tableProperties[tableKey] = PerTableProperties{
		addPathCapable: make(map[int]bool),
		localIP:        localIP,
		localHash:      fmt.Sprintf("%x", md5.Sum([]byte(localIP))),
	}
	p.tableLock.Unlock()

	gotIP, gotHash := p.peerLocal(tableKey)
	if gotIP != localIP {
		t.Errorf("before PeerDown: localIP = %v, want %v", gotIP, localIP)
	}
	if gotHash == "" {
		t.Errorf("before PeerDown: localHash should not be empty")
	}

	// Simulate PeerDown cleanup
	p.tableLock.Lock()
	delete(p.tableProperties, tableKey)
	p.tableLock.Unlock()

	gotIP, gotHash = p.peerLocal(tableKey)
	if gotIP != "" {
		t.Errorf("after PeerDown: localIP = %v, want empty", gotIP)
	}
	if gotHash != "" {
		t.Errorf("after PeerDown: localHash = %v, want empty", gotHash)
	}
}
