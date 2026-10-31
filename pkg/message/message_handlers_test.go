package message

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sync"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/mcastvpn"
)

// recordingPublisher captures PublishMessage calls for test assertions.
type recordingPublisher struct {
	mu   sync.Mutex
	msgs []recordedMsg
}

type recordedMsg struct {
	msgType int
	payload []byte
}

func (r *recordingPublisher) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	payload := make([]byte, len(msg))
	copy(payload, msg)
	r.msgs = append(r.msgs, recordedMsg{msgType: msgType, payload: payload})
	return nil
}

func (r *recordingPublisher) Stop() {}

// makePeerHeader constructs a PerPeerHeader with the given flags byte.
func makePeerHeader(t *testing.T, peerType bmp.PeerType, flagsByte byte) *bmp.PerPeerHeader {
	t.Helper()
	data := []byte{
		byte(peerType), // Peer Type
		flagsByte,      // Flags byte
	}
	data = append(data, make([]byte, 8)...)     // PeerDistinguisher
	data = append(data, make([]byte, 16)...)    // PeerAddress
	data = append(data, 0x00, 0x00, 0xFD, 0xE8) // Peer AS = 65000
	data = append(data, 0x0a, 0x00, 0x00, 0x01) // PeerBGPID
	data = append(data, make([]byte, 8)...)     // PeerTimestamp
	ph, err := bmp.UnmarshalPerPeerHeader(data)
	if err != nil {
		t.Fatalf("UnmarshalPerPeerHeader: %v", err)
	}
	return attachDefaultTestIdentity(ph)
}

// TestUnicastPrefixEqual_Symmetric verifies Equal() detects mismatches in both directions.
func TestUnicastPrefixEqual_Symmetric(t *testing.T) {
	tests := []struct {
		name string
		a, b UnicastPrefix
	}{
		{name: "IsIPv4", a: UnicastPrefix{IsIPv4: false}, b: UnicastPrefix{IsIPv4: true}},
		{name: "IsNexthopIPv4", a: UnicastPrefix{IsNexthopIPv4: false}, b: UnicastPrefix{IsNexthopIPv4: true}},
		{name: "IsAdjRIBInPost", a: UnicastPrefix{IsAdjRIBInPost: false}, b: UnicastPrefix{IsAdjRIBInPost: true}},
		{name: "IsAdjRIBOutPost", a: UnicastPrefix{IsAdjRIBOutPost: false}, b: UnicastPrefix{IsAdjRIBOutPost: true}},
		{name: "IsAdjRIBOut", a: UnicastPrefix{IsAdjRIBOut: false}, b: UnicastPrefix{IsAdjRIBOut: true}},
		{name: "IsLocRIB", a: UnicastPrefix{IsLocRIB: false}, b: UnicastPrefix{IsLocRIB: true}},
		{name: "IsLocRIBFiltered", a: UnicastPrefix{IsLocRIBFiltered: false}, b: UnicastPrefix{IsLocRIBFiltered: true}},
		{name: "TableName", a: UnicastPrefix{TableName: "VRF-A"}, b: UnicastPrefix{TableName: "VRF-B"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eq1, diffs1 := tt.a.Equal(&tt.b)
			eq2, diffs2 := tt.b.Equal(&tt.a)
			if eq1 {
				t.Errorf("a.Equal(b) = true, want false; diffs: %v", diffs1)
			}
			if eq2 {
				t.Errorf("b.Equal(a) = true, want false; diffs: %v", diffs2)
			}
			if len(diffs1) == 0 {
				t.Error("a.Equal(b) returned no diffs")
			}
			if len(diffs2) == 0 {
				t.Error("b.Equal(a) returned no diffs")
			}
		})
	}
}

// TestUnicastPrefixEqual_IdenticalFlags verifies Equal() returns true for identical values.
func TestUnicastPrefixEqual_IdenticalFlags(t *testing.T) {
	a := UnicastPrefix{
		IsIPv4: true, IsNexthopIPv4: true, IsAdjRIBInPost: true,
		IsAdjRIBOutPost: true, IsAdjRIBOut: true, IsLocRIB: true,
		IsLocRIBFiltered: true, TableName: "default",
	}
	eq, diffs := a.Equal(&a)
	if !eq {
		t.Errorf("Equal() = false for identical values; diffs: %v", diffs)
	}
}

func TestUnicastPrefixEqual_Nil(t *testing.T) {
	a := UnicastPrefix{}
	eq, _ := a.Equal(nil)
	if eq {
		t.Error("Equal(nil) = true, want false")
	}
}

// TestMVPN_RIBFlags_AllFive verifies MVPN handler extracts all 5 RIB flags.
func TestMVPN_RIBFlags_AllFive(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	// AdjRIBOut Post-Policy (O=1, L=1)
	phAdjOut := makePeerHeader(t, bmp.PeerType0, 0x50)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	// MVPN Type 1 route: RD (8) + Originator IP (4) = 12 bytes
	reachWithRoute := []byte{
		0x00, 0x01, // AFI: 1
		0x81,                   // SAFI: 129
		0x04,                   // NH Length: 4
		0x0a, 0x00, 0x00, 0x01, // NextHop
		0x00, // Reserved
		0x01, // Route Type: 1 (Intra-AS I-PMSI A-D)
		0x0C, // Length: 12
		// RD (8 bytes)
		0x00, 0x02, 0x00, 0x00, 0xFD, 0xE8, 0x00, 0x64,
		// Originator IP (4 bytes)
		0x0a, 0x00, 0x00, 0x01,
	}
	nlri2, err := bgp.UnmarshalMPReachNLRI(reachWithRoute, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}

	msgs2, err := p.mvpn(nlri2, 0, phAdjOut, update)
	if err != nil {
		t.Fatalf("mvpn() error: %v", err)
	}
	if len(msgs2) < 1 {
		t.Fatal("mvpn() returned 0 messages")
	}
	r := msgs2[0]
	if !r.IsAdjRIBOut {
		t.Error("IsAdjRIBOut = false, want true")
	}
	if !r.IsAdjRIBOutPost {
		t.Error("IsAdjRIBOutPost = false, want true")
	}
	if r.IsAdjRIBInPost {
		t.Error("IsAdjRIBInPost = true, want false for O=1")
	}
	if r.IsLocRIB {
		t.Error("IsLocRIB = true, want false for PeerType0")
	}
	if r.IsLocRIBFiltered {
		t.Error("IsLocRIBFiltered = true, want false for PeerType0")
	}
}

// TestMCASTVPN_Nexthop verifies the mcastvpn handler extracts the nexthop correctly.
func TestMCASTVPN_Nexthop(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	// MCAST-VPN (SAFI 5) Type 1 route: RD(8) + OriginatorIP(4) = 12 bytes
	reachWithRoute := []byte{
		0x00, 0x01, // AFI: 1
		0x05,                   // SAFI: 5
		0x04,                   // NH Length: 4
		0x0a, 0x00, 0x00, 0x01, // NextHop: 10.0.0.1
		0x00, // Reserved
		0x01, // Route Type: 1 (Intra-AS I-PMSI A-D)
		0x0C, // Length: 12
		// RD (8 bytes)
		0x00, 0x02, 0x00, 0x00, 0xFD, 0xE8, 0x00, 0x64,
		// Originator IP (4 bytes)
		0x0a, 0x00, 0x00, 0x01,
	}
	nlri, err := bgp.UnmarshalMPReachNLRI(reachWithRoute, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}

	msgs, err := p.mcastvpn(nlri, 0, ph, update)
	if err != nil {
		t.Fatalf("mcastvpn() error: %v", err)
	}
	if len(msgs) < 1 {
		t.Fatal("mcastvpn() returned 0 messages")
	}
	if msgs[0].Nexthop != "10.0.0.1" {
		t.Errorf("Nexthop = %q, want '10.0.0.1'", msgs[0].Nexthop)
	}
	if !msgs[0].IsNexthopIPv4 {
		t.Error("IsNexthopIPv4 = false, want true")
	}
}

// TestL3VPN_TableName verifies L3VPN handler sets TableName for LocRIB peers.
func TestL3VPN_TableName(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	phLocRIB := makePeerHeader(t, bmp.PeerType3, 0x00)

	tableKey := phLocRIB.GetPeerBGPIDString() + phLocRIB.GetPeerDistinguisherString()
	p.tableLock.Lock()
	p.tableProperties[tableKey] = PerTableProperties{
		addPathCapable: make(map[int]bool),
		tableInfoTLVs: []bmp.InformationalTLV{
			{InformationType: 3, Information: []byte("VRF-L3VPN")},
		},
	}
	p.tableLock.Unlock()

	// L3VPN (AFI=1, SAFI=128) with one route
	reachBytes := []byte{
		0x00, 0x01, // AFI: 1
		0x80,                                           // SAFI: 128
		0x0C,                                           // NH Length: 12 (RD 8 + IPv4 4)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // RD
		0x0a, 0x00, 0x00, 0x01, // NextHop
		0x00, // Reserved
		// One L3VPN prefix: label(3) + RD(8) + prefix
		// PrefixLen = 88 bits (24 label + 64 RD + 0 prefix) — but we need at least a /0
		// Actually: prefixLen(1) + label(3) + RD(8) + prefix bytes
		0x58,             // PrefixLen: 88 = 24(label) + 64(RD)
		0x00, 0x01, 0x01, // Label: 16 (bottom-of-stack)
		0x00, 0x02, 0x00, 0x00, 0xFD, 0xE8, 0x00, 0x64, // RD: 2:65000:100
	}
	nlri, err := bgp.UnmarshalMPReachNLRI(reachBytes, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	msgs, err := p.l3vpn(nlri, 0, phLocRIB, update)
	if err != nil {
		t.Fatalf("l3vpn() error: %v", err)
	}
	if len(msgs) < 1 {
		t.Fatal("l3vpn() returned 0 messages")
	}
	if msgs[0].TableName != "VRF-L3VPN" {
		t.Errorf("TableName = %q, want %q", msgs[0].TableName, "VRF-L3VPN")
	}
	if !msgs[0].IsLocRIB {
		t.Error("IsLocRIB = false, want true")
	}
}

// TestUnicast_TableName verifies unicast handler sets TableName for LocRIB peers.
func TestUnicast_TableName(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	phLocRIB := makePeerHeader(t, bmp.PeerType3, 0x00)

	tableKey := phLocRIB.GetPeerBGPIDString() + phLocRIB.GetPeerDistinguisherString()
	p.tableLock.Lock()
	p.tableProperties[tableKey] = PerTableProperties{
		addPathCapable: make(map[int]bool),
		tableInfoTLVs: []bmp.InformationalTLV{
			{InformationType: 3, Information: []byte("default")},
		},
	}
	p.tableLock.Unlock()

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

	msgs, err := p.unicast(nlri, 0, phLocRIB, update, false)
	if err != nil {
		t.Fatalf("unicast() error: %v", err)
	}
	if len(msgs) < 1 {
		t.Fatal("unicast() returned 0 messages")
	}
	if msgs[0].TableName != "default" {
		t.Errorf("TableName = %q, want %q", msgs[0].TableName, "default")
	}
	if !msgs[0].IsLocRIB {
		t.Error("IsLocRIB = false, want true")
	}
}

// TestBaseNLRI_TableName verifies legacy IPv4 NLRI handler sets TableName for LocRIB peers.
func TestBaseNLRI_TableName(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	phLocRIB := makePeerHeader(t, bmp.PeerType3, 0x00)

	tableKey := phLocRIB.GetPeerBGPIDString() + phLocRIB.GetPeerDistinguisherString()
	p.tableLock.Lock()
	p.tableProperties[tableKey] = PerTableProperties{
		addPathCapable: make(map[int]bool),
		tableInfoTLVs: []bmp.InformationalTLV{
			{InformationType: 3, Information: []byte("global")},
		},
	}
	p.tableLock.Unlock()

	// Simulate legacy IPv4 update with one /24 prefix in NLRI field
	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{
			Nexthop: "10.0.0.1",
		},
		NLRI: []byte{0x18, 0xc0, 0xa8, 0x01}, // 192.168.1.0/24
	}

	msgs, err := p.nlri(0, phLocRIB, update)
	if err != nil {
		t.Fatalf("nlri() error: %v", err)
	}
	if len(msgs) < 1 {
		t.Fatal("nlri() returned 0 messages")
	}
	if msgs[0].TableName != "global" {
		t.Errorf("TableName = %q, want %q", msgs[0].TableName, "global")
	}
	if !msgs[0].IsLocRIB {
		t.Error("IsLocRIB = false, want true")
	}
}

// TestBaseNLRI_EoR verifies legacy IPv4 EoR debug logging path.
func TestBaseNLRI_EoR(t *testing.T) {
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
	if !msgs[0].IsEOR {
		t.Error("IsEOR = false, want true")
	}
	if msgs[0].PeerIP != ph.GetPeerAddrString() {
		t.Errorf("PeerIP = %q, want %q", msgs[0].PeerIP, ph.GetPeerAddrString())
	}
}

// TestMVPN_LocRIB_TableName verifies MVPN handler sets TableName for LocRIB peers.
func TestMVPN_LocRIB_TableName(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	phLocRIB := makePeerHeader(t, bmp.PeerType3, 0x00)

	tableKey := phLocRIB.GetPeerBGPIDString() + phLocRIB.GetPeerDistinguisherString()
	p.tableLock.Lock()
	p.tableProperties[tableKey] = PerTableProperties{
		addPathCapable: make(map[int]bool),
		tableInfoTLVs: []bmp.InformationalTLV{
			{InformationType: 3, Information: []byte("VRF-MVPN")},
		},
	}
	p.tableLock.Unlock()

	// MVPN Type 1 route with LocRIB peer
	reachBytes := []byte{
		0x00, 0x01, // AFI: 1
		0x81,                   // SAFI: 129
		0x04,                   // NH Length: 4
		0x0a, 0x00, 0x00, 0x01, // NextHop
		0x00,                                           // Reserved
		0x01,                                           // Route Type: 1
		0x0C,                                           // Length: 12
		0x00, 0x02, 0x00, 0x00, 0xFD, 0xE8, 0x00, 0x64, // RD
		0x0a, 0x00, 0x00, 0x01, // Originator IP
	}
	nlri, err := bgp.UnmarshalMPReachNLRI(reachBytes, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	msgs, err := p.mvpn(nlri, 0, phLocRIB, update)
	if err != nil {
		t.Fatalf("mvpn() error: %v", err)
	}
	if len(msgs) < 1 {
		t.Fatal("mvpn() returned 0 messages")
	}
	if msgs[0].TableName != "VRF-MVPN" {
		t.Errorf("TableName = %q, want %q", msgs[0].TableName, "VRF-MVPN")
	}
	if !msgs[0].IsLocRIB {
		t.Error("IsLocRIB = false, want true")
	}
}

// TestProcessMPUpdate_L3VPN_EoR verifies L3VPN EoR is handled at debug level.
func TestProcessMPUpdate_L3VPN_EoR(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	// L3VPN MP_UNREACH with empty withdrawn routes — triggers "NLRI length is 0"
	unreachBytes := []byte{
		0x00, 0x01, // AFI: 1
		0x80, // SAFI: 128
	}
	nlri, err := bgp.UnmarshalMPUnReachNLRI(unreachBytes, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPUnReachNLRI: %v", err)
	}

	// Should not panic — exercises the L3VPN EoR error path
	p.processMPUpdate(nlri, 1, ph, update)
}

// TestUnicast_EoR_RIBFlags verifies EoR messages carry RIB flags and IsIPv4.
func TestUnicast_EoR_RIBFlags(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	// AdjRIBOut Post-Policy (O=1, L=1) — flags byte 0x50
	ph := makePeerHeader(t, bmp.PeerType0, 0x50)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	nlri := &mockMPNLRI{
		isIPv6:       false,
		unicastRoute: &base.MPNLRI{NLRI: []base.Route{}},
	}

	msgs, err := p.unicast(nlri, 0, ph, update, false)
	if err != nil {
		t.Fatalf("unicast() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("unicast() returned %d messages, want 1", len(msgs))
	}
	r := msgs[0]
	if !r.IsEOR {
		t.Error("IsEOR = false, want true")
	}
	if !r.IsIPv4 {
		t.Error("IsIPv4 = false, want true for IPv4")
	}
	if r.PeerIP != ph.GetPeerAddrString() {
		t.Errorf("PeerIP = %q, want %q", r.PeerIP, ph.GetPeerAddrString())
	}
	if !r.IsAdjRIBOut {
		t.Error("IsAdjRIBOut = false, want true")
	}
	if !r.IsAdjRIBOutPost {
		t.Error("IsAdjRIBOutPost = false, want true")
	}
}

// TestUnicast_EoR_LocRIB verifies EoR sets TableName for LocRIB peers.
func TestUnicast_EoR_LocRIB(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	ph := makePeerHeader(t, bmp.PeerType3, 0x00)
	tableKey := ph.GetPeerBGPIDString() + ph.GetPeerDistinguisherString()
	p.tableLock.Lock()
	p.tableProperties[tableKey] = PerTableProperties{
		addPathCapable: make(map[int]bool),
		tableInfoTLVs: []bmp.InformationalTLV{
			{InformationType: 3, Information: []byte("VRF-Test")},
		},
	}
	p.tableLock.Unlock()

	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	nlri := &mockMPNLRI{
		isIPv6:       false,
		unicastRoute: &base.MPNLRI{NLRI: []base.Route{}},
	}

	msgs, err := p.unicast(nlri, 0, ph, update, false)
	if err != nil {
		t.Fatalf("unicast() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("unicast() returned %d messages, want 1", len(msgs))
	}
	r := msgs[0]
	if !r.IsEOR {
		t.Error("IsEOR = false, want true")
	}
	if !r.IsLocRIB {
		t.Error("IsLocRIB = false, want true for PeerType3")
	}
	if r.TableName != "VRF-Test" {
		t.Errorf("TableName = %q, want %q", r.TableName, "VRF-Test")
	}
}

// TestMVPN_EoR_RIBFlags verifies MVPN EoR messages carry RIB flags.
func TestMVPN_EoR_RIBFlags(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	// AdjRIBOut Post-Policy (O=1, L=1)
	ph := makePeerHeader(t, bmp.PeerType0, 0x50)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	nlri := &mockMPNLRI{
		mvpnRoute: &mcastvpn.Route{Route: []*mcastvpn.NLRI{}},
	}

	msgs, err := p.mvpn(nlri, 0, ph, update)
	if err != nil {
		t.Fatalf("mvpn() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("mvpn() returned %d messages, want 1", len(msgs))
	}
	r := msgs[0]
	if !r.IsEOR {
		t.Error("IsEOR = false, want true")
	}
	if !r.IsIPv4 {
		t.Error("IsIPv4 = false, want true for IPv4 MVPN EoR")
	}
	if !r.IsNexthopIPv4 {
		t.Error("IsNexthopIPv4 = false, want true for IPv4 MVPN EoR")
	}
	if !r.IsAdjRIBOut {
		t.Error("IsAdjRIBOut = false, want true")
	}
	if !r.IsAdjRIBOutPost {
		t.Error("IsAdjRIBOutPost = false, want true")
	}
	if r.IsLocRIB {
		t.Error("IsLocRIB = true, want false for PeerType0")
	}
}

// TestProcessMPUpdate_UnicastBranches exercises the consolidated
// case 1, 2, 16, 17 branch of processMPUpdate for all AFI/SAFI combinations:
// AFI=1/SAFI=1 (IPv4 Unicast), AFI=2/SAFI=1 (IPv6 Unicast),
// AFI=1/SAFI=4 (IPv4 Labeled Unicast), AFI=2/SAFI=4 (IPv6 Labeled Unicast).
// Each case feeds a non-EoR MP_REACH_NLRI through processMPUpdate and asserts
// the recorded publish. The `labeled := nlri.GetAFISAFIType() >= 16` shortcut
// is observable via the presence/absence of parsed Labels; splitAF topic
// selection makes IPv4 vs IPv6 dispatch observable via the msg type.
func TestProcessMPUpdate_UnicastBranches(t *testing.T) {
	// IPv4 nexthop (1.1.1.1) and IPv6 nexthop (2001::1) for MP_REACH payloads.
	nhV4 := []byte{0x01, 0x01, 0x01, 0x01}
	nhV6 := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	// IPv4 unicast NLRI: 10.0.0.0/8 => [prefix_len_bits, prefix_bytes...]
	nlriV4Unicast := []byte{0x08, 0x0A}
	// IPv6 unicast NLRI: 2001::/16
	nlriV6Unicast := []byte{0x10, 0x20, 0x01}
	// IPv4 labeled unicast NLRI: length 56 bits (24 label + 32 prefix),
	// label=3 BoS, prefix 10.0.0.0/32. Mirrors pkg/unicast/unicast_test.go fixture.
	nlriV4Labeled := []byte{0x38, 0x00, 0x00, 0x31, 0x0a, 0x00, 0x00, 0x00}
	// IPv6 labeled unicast NLRI: length 40 bits (24 label + 16 prefix),
	// label=3 BoS, prefix 2001::/16.
	nlriV6Labeled := []byte{0x28, 0x00, 0x00, 0x31, 0x20, 0x01}

	buildReach := func(afi uint16, safi uint8, nh, nlri []byte) []byte {
		b := []byte{byte(afi >> 8), byte(afi), safi, byte(len(nh))}
		b = append(b, nh...)
		b = append(b, 0x00) // reserved
		b = append(b, nlri...)
		return b
	}

	tests := []struct {
		name          string
		reach         []byte
		wantIsIPv4    bool
		wantTopicType int
		wantLabeled   bool
	}{
		{"IPv4 Unicast", buildReach(1, 1, nhV4, nlriV4Unicast), true, bmp.UnicastPrefixV4Msg, false},
		{"IPv6 Unicast", buildReach(2, 1, nhV6, nlriV6Unicast), false, bmp.UnicastPrefixV6Msg, false},
		{"IPv4 Labeled Unicast", buildReach(1, 4, nhV4, nlriV4Labeled), true, bmp.UnicastPrefixV4Msg, true},
		{"IPv6 Labeled Unicast", buildReach(2, 4, nhV6, nlriV6Labeled), false, bmp.UnicastPrefixV6Msg, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingPublisher{}
			p := NewProducer(rec, true).(*producer)

			ph := makePeerHeader(t, bmp.PeerType0, 0x00)
			update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

			nlri, err := bgp.UnmarshalMPReachNLRI(tt.reach, false, map[int]bool{})
			if err != nil {
				t.Fatalf("UnmarshalMPReachNLRI: %v", err)
			}

			p.processMPUpdate(nlri, 0, ph, update)

			if len(rec.msgs) != 1 {
				t.Fatalf("published %d messages, want 1", len(rec.msgs))
			}
			if rec.msgs[0].msgType != tt.wantTopicType {
				t.Errorf("topic type = %d, want %d", rec.msgs[0].msgType, tt.wantTopicType)
			}
			var got UnicastPrefix
			if err := json.Unmarshal(rec.msgs[0].payload, &got); err != nil {
				t.Fatalf("Unmarshal published message: %v", err)
			}
			if got.IsIPv4 != tt.wantIsIPv4 {
				t.Errorf("IsIPv4 = %v, want %v", got.IsIPv4, tt.wantIsIPv4)
			}
			if got.Action != "add" {
				t.Errorf("Action = %q, want %q", got.Action, "add")
			}
			hasLabels := len(got.Labels) > 0
			if hasLabels != tt.wantLabeled {
				t.Errorf("labels present = %v (labels=%v), want %v", hasLabels, got.Labels, tt.wantLabeled)
			}
		})
	}
}

func TestProcessMPUpdate_MPUnreachEORTopics(t *testing.T) {
	tests := []struct {
		name          string
		unreach       []byte
		wantTopicType int
		wantIsIPv4    bool
		wantL3VPN     bool
	}{
		{"IPv4 Unicast", []byte{0x00, 0x01, 0x01}, bmp.UnicastPrefixV4Msg, true, false},
		{"IPv4 Labeled Unicast", []byte{0x00, 0x01, 0x04}, bmp.UnicastPrefixV4Msg, true, false},
		{"IPv6 Unicast", []byte{0x00, 0x02, 0x01}, bmp.UnicastPrefixV6Msg, false, false},
		{"VPNv4", []byte{0x00, 0x01, 0x80}, bmp.L3VPNV4Msg, true, true},
		{"VPNv6", []byte{0x00, 0x02, 0x80}, bmp.L3VPNV6Msg, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingPublisher{}
			p := NewProducer(rec, true).(*producer)

			ph := makePeerHeader(t, bmp.PeerType0, 0x00)
			update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

			nlri, err := bgp.UnmarshalMPUnReachNLRI(tt.unreach, map[int]bool{})
			if err != nil {
				t.Fatalf("UnmarshalMPUnReachNLRI: %v", err)
			}

			p.processMPUpdate(nlri, 1, ph, update)

			if len(rec.msgs) != 1 {
				t.Fatalf("published %d messages, want 1", len(rec.msgs))
			}
			if rec.msgs[0].msgType != tt.wantTopicType {
				t.Errorf("topic type = %d, want %d", rec.msgs[0].msgType, tt.wantTopicType)
			}

			if tt.wantL3VPN {
				var got L3VPNPrefix
				if err := json.Unmarshal(rec.msgs[0].payload, &got); err != nil {
					t.Fatalf("Unmarshal published L3VPN message: %v", err)
				}
				if !got.IsEOR {
					t.Error("IsEOR = false, want true")
				}
				if got.IsIPv4 != tt.wantIsIPv4 {
					t.Errorf("IsIPv4 = %v, want %v", got.IsIPv4, tt.wantIsIPv4)
				}
				if got.PeerIP != ph.GetPeerAddrString() {
					t.Errorf("PeerIP = %q, want %q", got.PeerIP, ph.GetPeerAddrString())
				}
				return
			}

			var got UnicastPrefix
			if err := json.Unmarshal(rec.msgs[0].payload, &got); err != nil {
				t.Fatalf("Unmarshal published unicast message: %v", err)
			}
			if !got.IsEOR {
				t.Error("IsEOR = false, want true")
			}
			if got.IsIPv4 != tt.wantIsIPv4 {
				t.Errorf("IsIPv4 = %v, want %v", got.IsIPv4, tt.wantIsIPv4)
			}
			if got.PeerIP != ph.GetPeerAddrString() {
				t.Errorf("PeerIP = %q, want %q", got.PeerIP, ph.GetPeerAddrString())
			}
		})
	}
}

// TestProcessMPUpdate_UnknownAFISAFI verifies default case logs warning for unknown types.
func TestProcessMPUpdate_UnknownAFISAFI(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	// AFI=99, SAFI=99 — unknown, should hit default case
	unreachBytes := []byte{
		0x00, 0x63, // AFI: 99
		0x63, // SAFI: 99
	}
	nlri, err := bgp.UnmarshalMPUnReachNLRI(unreachBytes, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPUnReachNLRI: %v", err)
	}

	// Should not panic — exercises the default case
	p.processMPUpdate(nlri, 1, ph, update)
}

func dPathAttribute(kind byte, value []byte) []byte {
	flags := byte(0x80)
	if kind == 36 {
		flags = 0xc0
	}
	return append([]byte{flags, kind, byte(len(value))}, value...)
}

func dPathReach(afi uint16, safi byte, nextHop, nlri []byte) []byte {
	value := []byte{byte(afi >> 8), byte(afi), safi, byte(len(nextHop))}
	value = append(value, nextHop...)
	value = append(value, 0)
	value = append(value, nlri...)
	return dPathAttribute(14, value)
}

func dPathUnreach(afi uint16, safi byte, nlri []byte) []byte {
	value := append([]byte{byte(afi >> 8), byte(afi), safi}, nlri...)
	return dPathAttribute(15, value)
}

func dPathPublish(t *testing.T, attributes, legacy []byte) []recordedMsg {
	t.Helper()
	return dPathPublishWithWithdraw(t, attributes, legacy, nil)
}

func dPathPublishWithWithdraw(t *testing.T, attributes, legacy, withdrawn []byte) []recordedMsg {
	t.Helper()
	// Include ORIGIN, an empty AS_PATH, and NEXT_HOP for legacy IPv4 NLRI.
	attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 0, 0x40, 3, 4, 192, 0, 2, 1}
	attrs = append(attrs, attributes...)
	wire := append([]byte{byte(len(withdrawn) >> 8), byte(len(withdrawn))}, withdrawn...)
	wire = append(wire, byte(len(attrs)>>8), byte(len(attrs)))
	wire = append(wire, attrs...)
	wire = append(wire, legacy...)
	update, err := bgp.UnmarshalBGPUpdate(wire)
	if err != nil {
		t.Fatalf("UnmarshalBGPUpdate: %v", err)
	}
	recorder := &recordingPublisher{}
	p := NewProducer(recorder, true).(*producer)
	p.produceRouteMonitorMessage(bmp.Message{
		PeerHeader: makePeerHeader(t, bmp.PeerType0, 0),
		Payload:    &bmp.RouteMonitor{Update: update},
	})
	return recorder.msgs
}

func TestDPathPublication(t *testing.T) {
	// RFC 10039 Section 4: a one-octet count precedes each seven-octet domain.
	// An unknown ISF SAFI is retained alongside ordered known domains.
	value := []byte{2, 0, 0, 0xfd, 0xe8, 0, 1, 128, 0, 0, 0xfd, 0xe9, 0, 2, 255,
		1, 0, 0, 0xfd, 0xea, 0, 3, 70}
	wantPath := &bgp.DPath{Segments: []bgp.DPathSegment{
		{Domains: []bgp.DPathDomain{{GlobalAdmin: 65000, LocalAdmin: 1, ISFSAFIType: 128}, {GlobalAdmin: 65001, LocalAdmin: 2, ISFSAFIType: 255}}},
		{Domains: []bgp.DPathDomain{{GlobalAdmin: 65002, LocalAdmin: 3, ISFSAFIType: 70}}},
	}}
	vpn4 := []byte{120, 0, 0, 0x31, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 192, 0, 2, 0}
	vpn6 := []byte{120, 0, 0, 0x31, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 0x20, 1, 0x0d, 0xb8}
	evpn := buildEVPNType5IPv6Wire()
	nh4 := []byte{192, 0, 2, 1}
	vpnNH4 := append(make([]byte, 8), nh4...)
	vpnNH6 := append(make([]byte, 8), []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}...)
	families := []struct {
		name    string
		afi     uint16
		safi    byte
		nh      []byte
		nlri    []byte
		msgType int
	}{
		{"VPNv4", 1, 128, vpnNH4, vpn4, bmp.L3VPNV4Msg},
		{"VPNv6 short prefix", 2, 128, vpnNH6, vpn6, bmp.L3VPNV6Msg},
		{"EVPN", 25, 70, nh4, evpn, bmp.EVPNMsg},
	}
	for _, family := range families {
		for _, withdraw := range []bool{false, true} {
			action := "add"
			if withdraw {
				action = "del"
			}
			t.Run(family.name+"/"+action, func(t *testing.T) {
				mp := dPathReach(family.afi, family.safi, family.nh, family.nlri)
				if withdraw {
					mp = dPathUnreach(family.afi, family.safi, family.nlri)
				}
				attributes := append(dPathAttribute(36, value), mp...)
				published := dPathPublish(t, attributes, nil)
				if len(published) != 1 {
					t.Fatalf("published %d messages, want 1", len(published))
				}
				if published[0].msgType != family.msgType {
					t.Errorf("message type = %d, want %d", published[0].msgType, family.msgType)
				}
				var got struct {
					Action string              `json:"action"`
					Attrs  *bgp.BaseAttributes `json:"base_attrs"`
				}
				if err := json.Unmarshal(published[0].payload, &got); err != nil {
					t.Fatalf("Unmarshal publication: %v", err)
				}
				if got.Action != action {
					t.Errorf("action = %q, want %q", got.Action, action)
				}
				if got.Attrs == nil {
					t.Fatal("base_attrs missing")
				}
				if !reflect.DeepEqual(got.Attrs.DPath, wantPath) || !bytes.Equal(got.Attrs.DPathAttr, value) || got.Attrs.DPathMalformed {
					t.Errorf("D-PATH not preserved in publication: %+v", got.Attrs)
				}
			})
		}
	}
}

func TestDPathPublicationRecovery(t *testing.T) {
	valid := []byte{1, 0, 0, 0xfd, 0xe8, 0, 1, 128}
	malformed := []byte{1, 0}
	vpn := []byte{120, 0, 0, 0x31, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 192, 0, 2, 0}
	vpnReach := dPathReach(1, 128, []byte{0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1}, vpn)
	vpn6 := []byte{120, 0, 0, 0x31, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 0x20, 1, 0x0d, 0xb8}
	vpn6NH := append(make([]byte, 8), []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}...)
	vpn6Reach := dPathReach(2, 128, vpn6NH, vpn6)
	evpnReach := dPathReach(25, 70, []byte{192, 0, 2, 1}, buildEVPNType5IPv6Wire())
	unicastReach := dPathReach(1, 1, []byte{192, 0, 2, 1}, []byte{24, 192, 0, 2})
	tests := []struct {
		name      string
		dpath     []byte
		mp        []byte
		legacy    []byte
		action    string
		malformed bool
		raw       []byte
		msgType   int
	}{
		{"malformed VPN", dPathAttribute(36, malformed), vpnReach, nil, "del", true, malformed, bmp.L3VPNV4Msg},
		{"malformed VPNv6", dPathAttribute(36, malformed), vpn6Reach, nil, "del", true, malformed, bmp.L3VPNV6Msg},
		{"malformed EVPN", dPathAttribute(36, malformed), evpnReach, nil, "del", true, malformed, bmp.EVPNMsg},
		{"first malformed duplicate retained", append(dPathAttribute(36, malformed), dPathAttribute(36, valid)...), vpnReach, nil, "del", true, malformed, bmp.L3VPNV4Msg},
		{"first valid duplicate retained", append(dPathAttribute(36, valid), dPathAttribute(36, malformed)...), vpnReach, nil, "add", false, valid, bmp.L3VPNV4Msg},
		{"unsupported MP family", dPathAttribute(36, valid), unicastReach, nil, "del", false, valid, bmp.UnicastPrefixV4Msg},
		{"unsupported legacy family", dPathAttribute(36, valid), nil, []byte{24, 192, 0, 2}, "del", false, valid, bmp.UnicastPrefixV4Msg},
		{"absent unchanged", nil, unicastReach, nil, "add", false, nil, bmp.UnicastPrefixV4Msg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			published := dPathPublish(t, append(tt.dpath, tt.mp...), tt.legacy)
			if len(published) != 1 {
				t.Fatalf("published %d messages, want 1", len(published))
			}
			if published[0].msgType != tt.msgType {
				t.Errorf("message type = %d, want %d", published[0].msgType, tt.msgType)
			}
			var got struct {
				Action string              `json:"action"`
				Attrs  *bgp.BaseAttributes `json:"base_attrs"`
			}
			if err := json.Unmarshal(published[0].payload, &got); err != nil {
				t.Fatalf("Unmarshal publication: %v", err)
			}
			if got.Action != tt.action || got.Attrs == nil {
				t.Fatalf("publication action = %q, attrs = %+v; want action %q and attributes", got.Action, got.Attrs, tt.action)
			}
			if got.Attrs.DPathMalformed != tt.malformed || !bytes.Equal(got.Attrs.DPathAttr, tt.raw) {
				t.Errorf("malformed = %v, raw = %x; want %v, %x", got.Attrs.DPathMalformed, got.Attrs.DPathAttr, tt.malformed, tt.raw)
			}
			wantDecoded := len(tt.raw) != 0 && !tt.malformed
			if (got.Attrs.DPath != nil) != wantDecoded {
				t.Errorf("decoded D-PATH present = %v, want %v", got.Attrs.DPath != nil, wantDecoded)
			}
		})
	}
}

func TestDPathPublicationMixedReachUnreach(t *testing.T) {
	value := []byte{1, 0, 0, 0xfd, 0xe8, 0, 1, 128}
	vpn := []byte{120, 0, 0, 0x31, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 192, 0, 2, 0}
	attrs := dPathAttribute(36, value)
	// The unsupported-family withdrawal precedes the supported-family announcement.
	attrs = append(attrs, dPathUnreach(1, 1, []byte{24, 198, 51, 100})...)
	attrs = append(attrs, dPathReach(1, 128, []byte{0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1}, vpn)...)
	published := dPathPublish(t, attrs, nil)
	if len(published) != 2 {
		t.Fatalf("published %d messages, want 2", len(published))
	}
	wantActions := map[int]string{bmp.L3VPNV4Msg: "add", bmp.UnicastPrefixV4Msg: "del"}
	for _, publication := range published {
		wantAction, ok := wantActions[publication.msgType]
		if !ok {
			t.Fatalf("unexpected or duplicate message type %d", publication.msgType)
		}
		delete(wantActions, publication.msgType)
		var got struct {
			Action string              `json:"action"`
			Prefix string              `json:"prefix"`
			Attrs  *bgp.BaseAttributes `json:"base_attrs"`
		}
		if err := json.Unmarshal(publication.payload, &got); err != nil {
			t.Fatalf("Unmarshal publication: %v", err)
		}
		if got.Action != wantAction {
			t.Errorf("action = %q for message type %d, want %q", got.Action, publication.msgType, wantAction)
		}
		if got.Attrs == nil || got.Attrs.DPath == nil || !bytes.Equal(got.Attrs.DPathAttr, value) || got.Attrs.DPathMalformed {
			t.Errorf("D-PATH not retained on %q publication: %+v", got.Action, got.Attrs)
		}
		wantPrefix := "192.0.2.0"
		if publication.msgType == bmp.UnicastPrefixV4Msg {
			wantPrefix = "198.51.100.0"
		}
		if got.Prefix != wantPrefix {
			t.Errorf("prefix = %q, want %q", got.Prefix, wantPrefix)
		}
	}
}

func TestDPathOperation(t *testing.T) {
	valid := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{DPath: &bgp.DPath{}}}
	tests := []struct {
		name   string
		update *bgp.Update
		afi    uint16
		safi   uint8
		want   int
	}{
		{"nil update", nil, 1, 1, AddPrefix},
		{"nil attributes", &bgp.Update{}, 1, 1, AddPrefix},
		{"absent", &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}, 1, 1, AddPrefix},
		{"malformed without decoded path", &bgp.Update{BaseAttributes: &bgp.BaseAttributes{DPathMalformed: true}}, 1, 128, DelPrefix},
		{"VPNv4", valid, 1, 128, AddPrefix},
		{"VPNv6", valid, 2, 128, AddPrefix},
		{"EVPN", valid, 25, 70, AddPrefix},
		{"unicast", valid, 1, 1, DelPrefix},
		{"EVPN SAFI with IPv4 AFI", valid, 1, 70, DelPrefix},
		{"VPN SAFI with L2VPN AFI", valid, 25, 128, DelPrefix},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := attributeErrorOperation(tt.update, tt.afi, tt.safi); got != tt.want {
				t.Errorf("attributeErrorOperation = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDPathUpdateIsNotEndOfRIB(t *testing.T) {
	malformed := dPathAttribute(36, []byte{1, 0})
	reach := dPathReach(25, 70, []byte{192, 0, 2, 1}, nil)
	if published := dPathPublish(t, append(malformed, reach...), nil); len(published) != 0 {
		t.Fatalf("empty MP_REACH published %d messages, want 0", len(published))
	}
	// RFC 4724 Section 2: an UPDATE carrying D-PATH besides the empty
	// MP_UNREACH is not an End-of-RIB marker.
	if published := dPathPublish(t, append(malformed, dPathUnreach(25, 70, nil)...), nil); len(published) != 0 {
		t.Fatalf("D-PATH with empty MP_UNREACH published %d messages, want 0", len(published))
	}
}

func TestEndOfRIBRequiresBareUpdate(t *testing.T) {
	publish := func(t *testing.T, attrs []byte) []recordedMsg {
		t.Helper()
		wire := append([]byte{0, 0, byte(len(attrs) >> 8), byte(len(attrs))}, attrs...)
		update, err := bgp.UnmarshalBGPUpdate(wire)
		if err != nil {
			t.Fatalf("UnmarshalBGPUpdate: %v", err)
		}
		recorder := &recordingPublisher{}
		p := NewProducer(recorder, true).(*producer)
		p.produceRouteMonitorMessage(bmp.Message{
			PeerHeader: makePeerHeader(t, bmp.PeerType0, 0),
			Payload:    &bmp.RouteMonitor{Update: update},
		})
		return recorder.msgs
	}
	t.Run("empty MP_UNREACH only", func(t *testing.T) {
		published := publish(t, dPathUnreach(25, 70, nil))
		findLegacy := false
		findEoR := false
		var got EndOfRIB
		var gotLegacy EVPNPrefix
		eorCount := 0
		eorLegacyCount := 0
		for _, msg := range published {
			if msg.msgType == bmp.EndOfRIBMsg {
				findEoR = true
				eorCount++
				if err := json.Unmarshal(msg.payload, &got); err != nil {
					t.Fatalf("Unmarshal publication: %v", err)
				}
				if got.AFI != 25 || got.SAFI != 70 {
					t.Errorf("AFI = %v, SAFI = %v; want 25, 70", got.AFI, got.SAFI)
				}
			}
			if msg.msgType == bmp.EVPNMsg && msg.payload != nil {
				findLegacy = true
				eorLegacyCount++
				if err := json.Unmarshal(msg.payload, &gotLegacy); err != nil {
					t.Fatalf("Unmarshal publication: %v", err)
				}
				if !gotLegacy.IsEOR || gotLegacy.Action != "del" {
					t.Errorf("IsEOR = %v, action = %q; want true, del", gotLegacy.IsEOR, gotLegacy.Action)
				}
			}
		}
		if !findEoR || !findLegacy || eorCount != 1 || eorLegacyCount != 1 {
			t.Fatalf("publications = %+v, want one EVPN End-of-RIB and one legacy EVPN EoR", published)
		}
	})
	t.Run("empty IPv4 UPDATE", func(t *testing.T) {
		published := publish(t, nil)
		findLegacy := false
		findEoR := false
		var got EndOfRIB
		var gotLegacy UnicastPrefix
		eorCount := 0
		eorLegacyCount := 0
		for _, msg := range published {
			if msg.msgType == bmp.EndOfRIBMsg {
				findEoR = true
				eorCount++
				if err := json.Unmarshal(msg.payload, &got); err != nil {
					t.Fatalf("Unmarshal publication: %v", err)
				}
				if got.AFI != 1 || got.SAFI != 1 {
					t.Errorf("AFI = %v, SAFI = %v; want 1, 1", got.AFI, got.SAFI)
				}
			}
			if msg.msgType == bmp.UnicastPrefixV4Msg && msg.payload != nil {
				findLegacy = true
				eorLegacyCount++
				if err := json.Unmarshal(msg.payload, &gotLegacy); err != nil {
					t.Fatalf("Unmarshal publication: %v", err)
				}
				if !gotLegacy.IsEOR {
					t.Errorf("IsEOR = %v want true", gotLegacy.IsEOR)
				}
			}
		}
		if !findEoR || !findLegacy || eorCount != 1 || eorLegacyCount != 1 {
			t.Fatalf("publications = %+v, want one IPv4 End-of-RIB and one legacy IPv4 EoR", published)
		}
	})
}

func TestDPathLegacyExplicitWithdrawals(t *testing.T) {
	malformed := dPathAttribute(36, []byte{1, 0})
	withdrawn := []byte{24, 198, 51, 100}
	decode := func(t *testing.T, records []recordedMsg) []UnicastPrefix {
		t.Helper()
		messages := make([]UnicastPrefix, len(records))
		for i, record := range records {
			if record.msgType != bmp.UnicastPrefixV4Msg {
				t.Fatalf("message type = %d, want IPv4 unicast", record.msgType)
			}
			if err := json.Unmarshal(record.payload, &messages[i]); err != nil {
				t.Fatalf("Unmarshal publication: %v", err)
			}
		}
		return messages
	}
	t.Run("withdrawal-only publishes no EOR", func(t *testing.T) {
		for _, attrs := range [][]byte{nil, malformed} {
			got := decode(t, dPathPublishWithWithdraw(t, attrs, nil, withdrawn))
			if len(got) != 1 || got[0].Action != "del" || got[0].Prefix != "198.51.100.0" || got[0].IsEOR {
				t.Errorf("publications = %+v, want one withdrawal of 198.51.100.0 without EOR", got)
			}
		}
	})
	t.Run("mixed announcement and withdrawal", func(t *testing.T) {
		got := decode(t, dPathPublishWithWithdraw(t, malformed, []byte{24, 192, 0, 2}, withdrawn))
		if len(got) != 2 {
			t.Fatalf("published %d messages, want 2", len(got))
		}
		wantPrefixes := map[string]bool{"198.51.100.0": true, "192.0.2.0": true}
		for _, message := range got {
			if !wantPrefixes[message.Prefix] || message.Action != "del" || message.IsEOR {
				t.Errorf("unexpected publication: %+v", message)
			}
			delete(wantPrefixes, message.Prefix)
		}
		if len(wantPrefixes) != 0 {
			t.Errorf("missing prefixes: %v", wantPrefixes)
		}
	})
}
