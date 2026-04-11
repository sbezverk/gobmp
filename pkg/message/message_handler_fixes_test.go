package message

import (
	"net"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/l3vpn"
	"github.com/sbezverk/gobmp/pkg/srpolicy"
)

// TestEqual_NilReceiver verifies Equal() does not panic on nil receiver (N10).
func TestEqual_NilReceiver(t *testing.T) {
	var u *UnicastPrefix
	nonNil := &UnicastPrefix{Prefix: "10.0.0.0"}

	// nil.Equal(non-nil) should return false, not panic
	eq, _ := u.Equal(nonNil)
	if eq {
		t.Error("nil.Equal(non-nil) = true, want false")
	}

	// nil.Equal(nil) should return true
	eq, _ = u.Equal(nil)
	if !eq {
		t.Error("nil.Equal(nil) = false, want true")
	}

	// non-nil.Equal(nil) should return false
	eq, _ = nonNil.Equal(nil)
	if eq {
		t.Error("non-nil.Equal(nil) = true, want false")
	}
}

// TestEqual_BaseAttributesNilMismatch verifies Equal() does not panic when one side
// has BaseAttributes set and the other is nil.
func TestEqual_BaseAttributesNilMismatch(t *testing.T) {
	withAttrs := &UnicastPrefix{BaseAttributes: &bgp.BaseAttributes{}}
	noAttrs := &UnicastPrefix{}

	eq, diffs := withAttrs.Equal(noAttrs)
	if eq {
		t.Error("Equal() = true, want false when u has BaseAttributes but ou does not")
	}
	if len(diffs) == 0 {
		t.Error("Equal() returned no diffs, want at least one")
	}

	eq, diffs = noAttrs.Equal(withAttrs)
	if eq {
		t.Error("Equal() = true, want false when u has no BaseAttributes but ou does")
	}
	if len(diffs) == 0 {
		t.Error("Equal() returned no diffs, want at least one")
	}
}

// TestFlowspec_RouterHash verifies flowspec messages include RouterHash (P3-20).
func TestFlowspec_RouterHash(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abcdef123456"

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	// Build a flowspec message with nil NLRI (withdraw-all path)
	fs := p.buildFlowspecMessage("del", &mockMPNLRI{isIPv6: false}, ph, update, nil)
	if fs.RouterHash != "abcdef123456" {
		t.Errorf("RouterHash = %q, want %q", fs.RouterHash, "abcdef123456")
	}
	if fs.RouterIP != "10.0.0.1" {
		t.Errorf("RouterIP = %q, want %q", fs.RouterIP, "10.0.0.1")
	}
}

// TestL3VPN_EoR verifies L3VPN produces an EoR message for empty NLRI (N6).
func TestL3VPN_EoR(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

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
	r := msgs[0]
	if !r.IsEOR {
		t.Error("IsEOR = false, want true")
	}
	if r.Action != "del" {
		t.Errorf("Action = %q, want %q", r.Action, "del")
	}
	if !r.IsIPv4 {
		t.Error("IsIPv4 = false, want true for IPv4")
	}
	if r.RouterHash != "abc123" {
		t.Errorf("RouterHash = %q, want %q", r.RouterHash, "abc123")
	}
}

// TestL3VPN_EoR_LocRIB verifies L3VPN EoR sets TableName for LocRIB peers.
func TestL3VPN_EoR_LocRIB(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

	ph := makePeerHeader(t, bmp.PeerType3, 0x00)
	tableKey := ph.GetPeerBGPIDString() + ph.GetPeerDistinguisherString()
	p.tableLock.Lock()
	p.tableProperties[tableKey] = PerTableProperties{
		addPathCapable: make(map[int]bool),
		tableInfoTLVs: []bmp.InformationalTLV{
			{InformationType: 3, Information: []byte("VRF-L3VPN-EoR")},
		},
	}
	p.tableLock.Unlock()

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
	if msgs[0].Action != "del" {
		t.Errorf("Action = %q, want \"del\"", msgs[0].Action)
	}
	if !msgs[0].IsLocRIB {
		t.Error("IsLocRIB = false, want true")
	}
	if msgs[0].TableName != "VRF-L3VPN-EoR" {
		t.Errorf("TableName = %q, want %q", msgs[0].TableName, "VRF-L3VPN-EoR")
	}
}

// TestL3VPN_EoR_IPv6 verifies L3VPN IPv6 EoR sets IsIPv4 = false.
func TestL3VPN_EoR_IPv6(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	p.speakerIP = "fd00::1"
	p.speakerHash = "ipv6hash"

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)

	nlri := &mockMPNLRI{
		l3vpnErr: l3vpn.ErrEmptyNLRI,
		isIPv6:   true,
	}

	msgs, err := p.l3vpn(nlri, 1, ph, &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}})
	if err != nil {
		t.Fatalf("l3vpn() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("l3vpn() returned %d messages, want 1", len(msgs))
	}
	if msgs[0].Action != "del" {
		t.Errorf("Action = %q, want \"del\"", msgs[0].Action)
	}
	if msgs[0].IsIPv4 {
		t.Error("IsIPv4 = true, want false for IPv6")
	}
}

// TestSRPolicy_NexthopIPv4_IndependentOfAFI verifies IsNexthopIPv4 is derived
// from actual nexthop, not from AFI (N21).
func TestSRPolicy_NexthopIPv4_IndependentOfAFI(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{
		TunnelEncapAttr: nil,
	}}

	// IPv4 AFI with IPv6 nexthop
	nlri := &mockMPNLRI{
		isIPv6:        false,
		isNextHopIPv6: true,
		srpolicyRoute: &srpolicy.NLRI73{Endpoint: []byte{10, 0, 0, 1}},
	}

	msgs, err := p.srpolicy(nlri, 0, ph, update)
	if err != nil {
		t.Fatalf("srpolicy() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("srpolicy() returned %d messages, want 1", len(msgs))
	}
	if !msgs[0].IsIPv4 {
		t.Error("IsIPv4 = false, want true (IPv4 AFI)")
	}
	if msgs[0].IsNexthopIPv4 {
		t.Error("IsNexthopIPv4 = true, want false (IPv6 nexthop with IPv4 AFI)")
	}
}

// TestSpeakerIP_SetOnce verifies speakerIP/speakerHash are set exactly once
// via sync.Once and subsequent PeerUp messages don't overwrite them (N8).
func TestSpeakerIP_SetOnce(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	// Build two PeerUp messages with different local IPs
	peerUpMsg1 := buildPeerUpMessage(t, "192.168.1.1")
	peerUpMsg2 := buildPeerUpMessage(t, "192.168.2.2")

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)

	msg1 := bmp.Message{PeerHeader: ph, Payload: peerUpMsg1}
	msg2 := bmp.Message{PeerHeader: ph, Payload: peerUpMsg2}

	p.producePeerMessage(peerUP, msg1)

	firstIP := p.speakerIP
	firstHash := p.speakerHash

	// Second PeerUp should NOT overwrite speakerIP
	p.producePeerMessage(peerUP, msg2)

	if p.speakerIP != firstIP {
		t.Errorf("speakerIP changed from %q to %q after second PeerUp", firstIP, p.speakerIP)
	}
	if p.speakerHash != firstHash {
		t.Errorf("speakerHash changed after second PeerUp")
	}
}

// buildPeerUpMessage constructs a minimal PeerUpMessage for testing.
func buildPeerUpMessage(t *testing.T, localIP string) *bmp.PeerUpMessage {
	t.Helper()
	// Build a minimal PeerUp with SentOpen and ReceivedOpen
	sentOpen := bgp.OpenMessage{
		Version:  4,
		MyAS:     65000,
		HoldTime: 90,
		BGPID:    []byte{10, 0, 0, 1},
	}
	recvOpen := bgp.OpenMessage{
		Version:  4,
		MyAS:     65001,
		HoldTime: 90,
		BGPID:    []byte{10, 0, 0, 2},
	}
	localAddr := make([]byte, 16)
	ip := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
	// Parse localIP as IPv4
	parts := parseIPv4(t, localIP)
	ip = append(ip, parts...)
	copy(localAddr, ip)

	return &bmp.PeerUpMessage{
		LocalAddress: localAddr,
		LocalPort:    179,
		RemotePort:   45678,
		SentOpen:     &sentOpen,
		ReceivedOpen: &recvOpen,
	}
}

// parseIPv4 parses a dotted-quad IPv4 into 4 bytes.
func parseIPv4(t *testing.T, s string) []byte {
	t.Helper()
	ip := net.ParseIP(s).To4()
	if ip == nil {
		t.Fatalf("parseIPv4: invalid address %q", s)
	}
	return []byte(ip)
}

// TestUnicast_ValidNLRI_Publishes verifies a valid unicast NLRI produces a
// message with correct fields, exercising the non-error publish path (H2).
func TestUnicast_ValidNLRI_Publishes(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

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

	msgs, err := p.unicast(nlri, 0, ph, update, false)
	if err != nil {
		t.Fatalf("unicast() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("unicast() returned %d messages, want 1", len(msgs))
	}
	if msgs[0].Prefix != "192.168.1.0" {
		t.Errorf("Prefix = %q, want %q", msgs[0].Prefix, "192.168.1.0")
	}
	if msgs[0].PrefixLen != 24 {
		t.Errorf("PrefixLen = %d, want 24", msgs[0].PrefixLen)
	}
	if !msgs[0].IsIPv4 {
		t.Error("IsIPv4 = false, want true")
	}
	if msgs[0].RouterHash != "abc123" {
		t.Errorf("RouterHash = %q, want %q", msgs[0].RouterHash, "abc123")
	}
}
