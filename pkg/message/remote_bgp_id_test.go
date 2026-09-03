package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/l3vpn"
)

// wantPeerBGPID is the PeerBGPID makePeerHeader encodes into every synthetic
// PerPeerHeader (10.0.0.1), so it is also what GetPeerBGPIDString() returns.
const wantPeerBGPID = "10.0.0.1"

// TestUnicast_RemoteBGPID_EOR verifies the unicast EoR message carries the
// advertising peer's BGP Identifier from the Per-Peer Header.
func TestUnicast_RemoteBGPID_EOR(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	reachBytes := []byte{0x00, 0x01, 0x01} // AFI=1 SAFI=1, no prefixes
	nlri, err := bgp.UnmarshalMPUnReachNLRI(reachBytes, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPUnReachNLRI: %v", err)
	}
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	msgs, err := p.unicast(nlri, 1, ph, update, false)
	if err != nil {
		t.Fatalf("unicast() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("unicast() returned %d messages, want 1", len(msgs))
	}
	if msgs[0].RemoteBGPID != wantPeerBGPID {
		t.Errorf("RemoteBGPID = %q, want %q", msgs[0].RemoteBGPID, wantPeerBGPID)
	}
}

// TestUnicast_RemoteBGPID_PerRoute verifies a unicast route message carries
// the advertising peer's BGP Identifier from the Per-Peer Header.
func TestUnicast_RemoteBGPID_PerRoute(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	// Unicast (AFI=1, SAFI=1) with one /24 prefix
	reachBytes := []byte{
		0x00, 0x01, // AFI: 1
		0x01,                   // SAFI: 1
		0x04,                   // NH Length: 4
		0x0a, 0x00, 0x00, 0x01, // NextHop
		0x00,                   // Reserved
		0x18, 0xc0, 0xa8, 0x01, // /24 prefix: 192.168.1.0/24
	}
	nlri, err := bgp.UnmarshalMPReachNLRI(reachBytes, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	msgs, err := p.unicast(nlri, 0, ph, update, false)
	if err != nil {
		t.Fatalf("unicast() error: %v", err)
	}
	if len(msgs) < 1 {
		t.Fatal("unicast() returned 0 messages")
	}
	if msgs[0].RemoteBGPID != wantPeerBGPID {
		t.Errorf("RemoteBGPID = %q, want %q", msgs[0].RemoteBGPID, wantPeerBGPID)
	}
}

// TestL3VPN_RemoteBGPID_EOR verifies the L3VPN EoR message carries the
// advertising peer's BGP Identifier from the Per-Peer Header.
func TestL3VPN_RemoteBGPID_EOR(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	nlri := &mockMPNLRI{
		l3vpnErr: l3vpn.ErrEmptyNLRI,
		isIPv6:   false,
	}

	msgs, err := p.l3vpn(nlri, 1, ph, &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}})
	if err != nil {
		t.Fatalf("l3vpn() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("l3vpn() returned %d messages, want 1", len(msgs))
	}
	if msgs[0].RemoteBGPID != wantPeerBGPID {
		t.Errorf("RemoteBGPID = %q, want %q", msgs[0].RemoteBGPID, wantPeerBGPID)
	}
}

// TestL3VPN_RemoteBGPID_PerRoute verifies an L3VPN route message carries the
// advertising peer's BGP Identifier from the Per-Peer Header.
func TestL3VPN_RemoteBGPID_PerRoute(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	// L3VPN (AFI=1, SAFI=128) with one route
	reachBytes := []byte{
		0x00, 0x01, // AFI: 1
		0x80,                                           // SAFI: 128
		0x0C,                                           // NH Length: 12 (RD 8 + IPv4 4)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // RD
		0x0a, 0x00, 0x00, 0x01, // NextHop
		0x00,             // Reserved
		0x58,             // PrefixLen: 88 = 24(label) + 64(RD)
		0x00, 0x01, 0x01, // Label: 16 (bottom-of-stack)
		0x00, 0x02, 0x00, 0x00, 0xFD, 0xE8, 0x00, 0x64, // RD: 2:65000:100
	}
	nlri, err := bgp.UnmarshalMPReachNLRI(reachBytes, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	msgs, err := p.l3vpn(nlri, 0, ph, update)
	if err != nil {
		t.Fatalf("l3vpn() error: %v", err)
	}
	if len(msgs) < 1 {
		t.Fatal("l3vpn() returned 0 messages")
	}
	if msgs[0].RemoteBGPID != wantPeerBGPID {
		t.Errorf("RemoteBGPID = %q, want %q", msgs[0].RemoteBGPID, wantPeerBGPID)
	}
}

// TestBaseNLRI_RemoteBGPID_EOR verifies the legacy IPv4 unicast EoR message
// carries the advertising peer's BGP Identifier from the Per-Peer Header.
func TestBaseNLRI_RemoteBGPID_EOR(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{},
		NLRI:           []byte{}, // Empty — EoR
	}

	msgs, err := p.nlri(0, ph, update)
	if err != nil {
		t.Fatalf("nlri() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("nlri() returned %d messages, want 1", len(msgs))
	}
	if msgs[0].RemoteBGPID != wantPeerBGPID {
		t.Errorf("RemoteBGPID = %q, want %q", msgs[0].RemoteBGPID, wantPeerBGPID)
	}
}

// TestBaseNLRI_RemoteBGPID_PerRoute verifies a legacy IPv4 unicast route
// message carries the advertising peer's BGP Identifier from the Per-Peer
// Header.
func TestBaseNLRI_RemoteBGPID_PerRoute(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{
			Nexthop: "10.0.0.1",
		},
		NLRI: []byte{0x18, 0xc0, 0xa8, 0x01}, // 192.168.1.0/24
	}

	msgs, err := p.nlri(0, ph, update)
	if err != nil {
		t.Fatalf("nlri() error: %v", err)
	}
	if len(msgs) < 1 {
		t.Fatal("nlri() returned 0 messages")
	}
	if msgs[0].RemoteBGPID != wantPeerBGPID {
		t.Errorf("RemoteBGPID = %q, want %q", msgs[0].RemoteBGPID, wantPeerBGPID)
	}
}
