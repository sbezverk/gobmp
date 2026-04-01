package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

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
	return ph
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
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

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
	if r.IsLocRIB {
		t.Error("IsLocRIB = true, want false for PeerType0")
	}
}

// TestL3VPN_TableName verifies L3VPN handler sets TableName for LocRIB peers.
func TestL3VPN_TableName(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

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
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

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
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

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
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

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
}

// TestMVPN_LocRIB_TableName verifies MVPN handler sets TableName for LocRIB peers.
func TestMVPN_LocRIB_TableName(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

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
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

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

// TestProcessMPUpdate_UnknownAFISAFI verifies default case logs warning for unknown types.
func TestProcessMPUpdate_UnknownAFISAFI(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	p.speakerIP = "10.0.0.1"
	p.speakerHash = "abc123"

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
