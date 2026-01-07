package message

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/evpn"
	"github.com/sbezverk/gobmp/pkg/flowspec"
	"github.com/sbezverk/gobmp/pkg/ls"
	"github.com/sbezverk/gobmp/pkg/mcastvpn"
	"github.com/sbezverk/gobmp/pkg/srpolicy"
	"github.com/sbezverk/gobmp/pkg/vpls"
)

// TestVPLSMessageProducer_RFC4761 tests VPLS message production for RFC 4761 format
func TestVPLSMessageProducer_RFC4761(t *testing.T) {
	// Create mock NLRI (RFC 4761 - 17 bytes)
	nlriBytes := []byte{
		0x00, 0x11, // Length: 17
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD Type 0 (8 bytes)
		0x00, 0x01, // VE ID: 1
		0x00, 0x00, // VE Block Offset: 0
		0x00, 0x0a, // VE Block Size: 10
		0x18, 0x6a, 0x00, // Label Base: 100,000 (0x186A0)
	}

	vplsRoute, err := vpls.UnmarshalVPLSNLRI(nlriBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal VPLS NLRI: %v", err)
	}

	// Create mock MPNLRI
	mockNLRI := &mockMPNLRI{
		vplsRoute: vplsRoute,
		nextHop:   "10.0.0.2",
		isIPv6:    false,
	}

	// Create mock PerPeerHeader
	peerHeader := &bmp.PerPeerHeader{
		PeerType:          0,
		PeerAS:            65000,
		PeerAddress:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2},
		PeerBGPID:         []byte{10, 0, 0, 2},
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}

	// Create mock Update with Extended Community
	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{
			ASPath: []uint32{65000},
		},
		PathAttributes: []bgp.PathAttribute{
			{
				AttributeType: 16, // Extended Community
				Attribute: []byte{
					0x80, 0x0a, // Type: Layer2 Info
					0x04,       // Encap: Ethernet
					0x01,       // Flags: C flag
					0x05, 0xdc, // MTU: 1500
					0x00, 0x00, // Reserved
				},
			},
		},
	}

	// Create producer
	p := &producer{
		speakerHash: "test-speaker-hash",
		speakerIP:   "10.1.1.1",
	}

	// Call vpls producer
	msgs, err := p.vpls(mockNLRI, 0, peerHeader, update)
	if err != nil {
		t.Fatalf("vpls() failed: %v", err)
	}

	// Verify results
	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}

	msg := msgs[0]

	// Verify common fields
	if msg.Action != "add" {
		t.Errorf("Action = %s, want add", msg.Action)
	}
	if msg.RouterHash != "test-speaker-hash" {
		t.Errorf("RouterHash = %s, want test-speaker-hash", msg.RouterHash)
	}
	if msg.PeerASN != 65000 {
		t.Errorf("PeerASN = %d, want 65000", msg.PeerASN)
	}
	if msg.Nexthop != "10.0.0.2" {
		t.Errorf("Nexthop = %s, want 10.0.0.2", msg.Nexthop)
	}

	// Verify VPLS-specific fields
	if msg.RFCType != "RFC4761" {
		t.Errorf("RFCType = %s, want RFC4761", msg.RFCType)
	}
	if msg.VEID == nil || *msg.VEID != 1 {
		t.Errorf("VEID = %v, want 1", msg.VEID)
	}
	if msg.VEBlockOffset == nil || *msg.VEBlockOffset != 0 {
		t.Errorf("VEBlockOffset = %v, want 0", msg.VEBlockOffset)
	}
	if msg.VEBlockSize == nil || *msg.VEBlockSize != 10 {
		t.Errorf("VEBlockSize = %v, want 10", msg.VEBlockSize)
	}
	if msg.LabelBase == nil || *msg.LabelBase != 100000 {
		t.Errorf("LabelBase = %v, want 100000", msg.LabelBase)
	}
	if msg.LabelBlockEnd == nil || *msg.LabelBlockEnd != 100009 {
		t.Errorf("LabelBlockEnd = %v, want 100009", msg.LabelBlockEnd)
	}

	// Verify Layer2 Info Extended Community
	if msg.EncapType == nil || *msg.EncapType != "Ethernet (802.3)" {
		t.Errorf("EncapType = %v, want Ethernet (802.3)", msg.EncapType)
	}
	if msg.ControlWord == nil || *msg.ControlWord != true {
		t.Errorf("ControlWord = %v, want true", msg.ControlWord)
	}
	if msg.SequencedDel == nil || *msg.SequencedDel != false {
		t.Errorf("SequencedDel = %v, want false", msg.SequencedDel)
	}
	if msg.MTU == nil || *msg.MTU != 1500 {
		t.Errorf("MTU = %v, want 1500", msg.MTU)
	}
}

// TestVPLSMessageProducer_RFC6074 tests VPLS message production for RFC 6074 format
func TestVPLSMessageProducer_RFC6074(t *testing.T) {
	// Create mock NLRI (RFC 6074 - 12 bytes)
	nlriBytes := []byte{
		0x00, 0x0c, // Length: 12
		0x00, 0x02, 0x00, 0x00, 0xfd, 0xe8, 0x00, 0x64, // RD Type 2 (8 bytes)
		0x0a, 0x00, 0x00, 0x03, // PE Address: 10.0.0.3
	}

	vplsRoute, err := vpls.UnmarshalVPLSNLRI(nlriBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal VPLS NLRI: %v", err)
	}

	mockNLRI := &mockMPNLRI{
		vplsRoute: vplsRoute,
		nextHop:   "10.0.0.3",
		isIPv6:    false,
	}

	peerHeader := &bmp.PerPeerHeader{
		PeerType:          0,
		PeerAS:            65000,
		PeerAddress:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 3},
		PeerBGPID:         []byte{10, 0, 0, 3},
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}

	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{
			ASPath: []uint32{65000},
		},
		PathAttributes: []bgp.PathAttribute{
			{
				AttributeType: 16, // Extended Community
				Attribute: []byte{
					0x80, 0x0a, // Type: Layer2 Info
					0x13,       // Encap: Ethernet VLAN (type 19)
					0x00,       // Flags: none
					0x05, 0xdc, // MTU: 1500
					0x00, 0x00, // Reserved
				},
			},
		},
	}

	p := &producer{
		speakerHash: "test-speaker-hash",
		speakerIP:   "10.1.1.1",
	}

	msgs, err := p.vpls(mockNLRI, 0, peerHeader, update)
	if err != nil {
		t.Fatalf("vpls() failed: %v", err)
	}

	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}

	msg := msgs[0]

	// Verify RFC 6074 specific fields
	if msg.RFCType != "RFC6074" {
		t.Errorf("RFCType = %s, want RFC6074", msg.RFCType)
	}
	if msg.PEAddress == nil || *msg.PEAddress != "10.0.0.3" {
		t.Errorf("PEAddress = %v, want 10.0.0.3", msg.PEAddress)
	}

	// RFC 6074 should not have VE ID fields
	if msg.VEID != nil {
		t.Error("VEID should be nil for RFC 6074")
	}

	// Verify Layer2 Info
	if msg.EncapType == nil || *msg.EncapType != "Ethernet VLAN (802.1Q)" {
		t.Errorf("EncapType = %v, want Ethernet VLAN (802.1Q)", msg.EncapType)
	}
}

// TestVPLSMessageProducer_Withdrawal tests VPLS withdrawal message
func TestVPLSMessageProducer_Withdrawal(t *testing.T) {
	nlriBytes := []byte{
		0x00, 0x11, // Length: 17
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD Type 0 (8 bytes)
		0x00, 0x01, // VE ID: 1
		0x00, 0x00, // VE Block Offset: 0
		0x00, 0x0a, // VE Block Size: 10
		0x18, 0x6a, 0x00, // Label Base: 100,000
	}

	vplsRoute, err := vpls.UnmarshalVPLSNLRI(nlriBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal VPLS NLRI: %v", err)
	}

	mockNLRI := &mockMPNLRI{
		vplsRoute: vplsRoute,
		nextHop:   "10.0.0.2",
		isIPv6:    false,
	}

	peerHeader := &bmp.PerPeerHeader{
		PeerAS:            65000,
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         make([]byte, 4),
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     make([]byte, 8),
	}

	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{},
		PathAttributes: []bgp.PathAttribute{},
	}

	p := &producer{}

	// Test withdrawal (operation = 1)
	msgs, err := p.vpls(mockNLRI, 1, peerHeader, update)
	if err != nil {
		t.Fatalf("vpls() failed: %v", err)
	}

	if msgs[0].Action != "del" {
		t.Errorf("Action = %s, want del", msgs[0].Action)
	}
}

// TestRoundTripVPLSPrefix tests JSON marshaling/unmarshaling
func TestRoundTripVPLSPrefix(t *testing.T) {
	veid := uint16(1)
	labelBase := uint32(100000)
	labelEnd := uint32(100009)
	encapType := "Ethernet (802.3)"
	controlWord := true
	mtu := uint16(1500)

	original := &VPLSPrefix{
		Action:        "add",
		RouterHash:    "test-hash",
		RouterIP:      "10.1.1.1",
		PeerASN:       65000,
		VPNRD:         "65000:100",
		RFCType:       "RFC4761",
		VEID:          &veid,
		LabelBase:     &labelBase,
		LabelBlockEnd: &labelEnd,
		EncapType:     &encapType,
		ControlWord:   &controlWord,
		MTU:           &mtu,
		IsIPv4:        true,
	}

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	recovered := &VPLSPrefix{}
	if err := json.Unmarshal(b, recovered); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !reflect.DeepEqual(original, recovered) {
		t.Logf("Differences: %+v", deep.Equal(original, recovered))
		t.Fatalf("Original and recovered do not match")
	}
}

// mockMPNLRI implements bgp.MPNLRI interface for testing
type mockMPNLRI struct {
	vplsRoute *vpls.Route
	nextHop   string
	isIPv6    bool
}

func (m *mockMPNLRI) GetAFISAFIType() int {
	return 23 // VPLS type
}

func (m *mockMPNLRI) GetNLRIVPLS() (*vpls.Route, error) {
	return m.vplsRoute, nil
}

func (m *mockMPNLRI) GetNextHop() string {
	return m.nextHop
}

func (m *mockMPNLRI) IsIPv6NLRI() bool {
	return m.isIPv6
}

func (m *mockMPNLRI) IsNextHopIPv6() bool {
	return m.isIPv6
}

// Implement other required MPNLRI methods (not used in vpls tests)
func (m *mockMPNLRI) GetNLRILU() (*base.MPNLRI, error)         { return nil, nil }
func (m *mockMPNLRI) GetNLRIUnicast() (*base.MPNLRI, error)    { return nil, nil }
func (m *mockMPNLRI) GetNLRIEVPN() (*evpn.Route, error)        { return nil, nil }
func (m *mockMPNLRI) GetNLRIL3VPN() (*base.MPNLRI, error)      { return nil, nil }
func (m *mockMPNLRI) GetNLRI71() (*ls.NLRI71, error)           { return nil, nil }
func (m *mockMPNLRI) GetNLRI73() (*srpolicy.NLRI73, error)     { return nil, nil }
func (m *mockMPNLRI) GetFlowspecNLRI() (*flowspec.NLRI, error) { return nil, nil }
func (m *mockMPNLRI) GetNLRIMCASTVPN() (*mcastvpn.Route, error) { return nil, nil }
func (m *mockMPNLRI) GetNLRIMulticast() (*base.MPNLRI, error)  { return nil, nil }
