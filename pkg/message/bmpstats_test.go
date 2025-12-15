package message

import (
	"encoding/binary"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// mockPublisher implements pub.Publisher interface for testing
type mockPublisher struct {
}

func (m *mockPublisher) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	return nil
}

func (m *mockPublisher) Stop() {
	// No-op for testing
}

// TestStatsType0_PrefixesRejectedInbound tests RFC 7854 Section 4.8 Type 0
func TestStatsType0_PrefixesRejectedInbound(t *testing.T) {
	p := &producer{
		speakerHash: "test-router",
		speakerIP:   "192.0.2.1",
		publisher:   &mockPublisher{},
	}

	// Create test BMP message with Stats Type 0
	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{
				InformationType: 0,
				InformationLength:  4,
				Information:     make([]byte, 4),
			},
		},
	}
	// Set value 12345 (uint32)
	binary.BigEndian.PutUint32(statsMsg.StatsTLV[0].Information, 12345)

	msg := bmp.Message{
		PeerHeader: &bmp.PerPeerHeader{
			PeerAS:   65001,
			PeerType: 0,
		},
		Payload: statsMsg,
	}

	// Create Stats struct
	m := Stats{
		RemoteASN:  msg.PeerHeader.PeerAS,
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
	}

	// Process TLV
	for _, tlv := range statsMsg.StatsTLV {
		if tlv.InformationType == 0 {
			m.PrefixesRejectedInbound = binary.BigEndian.Uint32(tlv.Information)
		}
	}

	// Verify
	if m.PrefixesRejectedInbound != 12345 {
		t.Errorf("Expected PrefixesRejectedInbound=12345, got %d", m.PrefixesRejectedInbound)
	}
}

// TestStatsType14_PrePolicyAdjRIBOut tests RFC 7854 Section 4.8 Type 14
func TestStatsType14_PrePolicyAdjRIBOut(t *testing.T) {
	p := &producer{
		speakerHash: "test-router",
		speakerIP:   "192.0.2.1",
		publisher:   &mockPublisher{},
	}

	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{
				InformationType: 14,
				InformationLength:  8,
				Information:     make([]byte, 8),
			},
		},
	}
	// Set value 987654321 (uint64)
	binary.BigEndian.PutUint64(statsMsg.StatsTLV[0].Information, 987654321)

	msg := bmp.Message{
		PeerHeader: &bmp.PerPeerHeader{
			PeerAS:   65001,
			PeerType: 0,
		},
		Payload: statsMsg,
	}

	m := Stats{
		RemoteASN:  msg.PeerHeader.PeerAS,
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
	}

	for _, tlv := range statsMsg.StatsTLV {
		if tlv.InformationType == 14 {
			m.PrePolicyAdjRIBOut = binary.BigEndian.Uint64(tlv.Information)
		}
	}

	if m.PrePolicyAdjRIBOut != 987654321 {
		t.Errorf("Expected PrePolicyAdjRIBOut=987654321, got %d", m.PrePolicyAdjRIBOut)
	}
}

// TestStatsType15_PostPolicyAdjRIBOut tests RFC 7854 Section 4.8 Type 15
func TestStatsType15_PostPolicyAdjRIBOut(t *testing.T) {
	p := &producer{
		speakerHash: "test-router",
		speakerIP:   "192.0.2.1",
		publisher:   &mockPublisher{},
	}

	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{
				InformationType: 15,
				InformationLength:  8,
				Information:     make([]byte, 8),
			},
		},
	}
	binary.BigEndian.PutUint64(statsMsg.StatsTLV[0].Information, 123456789)

	msg := bmp.Message{
		PeerHeader: &bmp.PerPeerHeader{
			PeerAS:   65001,
			PeerType: 0,
		},
		Payload: statsMsg,
	}

	m := Stats{
		RemoteASN:  msg.PeerHeader.PeerAS,
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
	}

	for _, tlv := range statsMsg.StatsTLV {
		if tlv.InformationType == 15 {
			m.PostPolicyAdjRIBOut = binary.BigEndian.Uint64(tlv.Information)
		}
	}

	if m.PostPolicyAdjRIBOut != 123456789 {
		t.Errorf("Expected PostPolicyAdjRIBOut=123456789, got %d", m.PostPolicyAdjRIBOut)
	}
}

// TestStatsType16_PrePolicyAdjRIBOutPerAFI removed - replaced with RFC-compliant tests in bmpstats_rfc_test.go
// Types 16 and 17 must use AFI/SAFI structure per RFC 8671, not simple uint64

// TestStatsType17_PostPolicyAdjRIBOutPerAFI removed - replaced with RFC-compliant tests in bmpstats_rfc_test.go
// Types 16 and 17 must use AFI/SAFI structure per RFC 8671, not simple uint64

// TestStatsMultipleTLVs tests handling multiple stat types in single message
func TestStatsMultipleTLVs(t *testing.T) {
	p := &producer{
		speakerHash: "test-router",
		speakerIP:   "192.0.2.1",
		publisher:   &mockPublisher{},
	}

	// Create message with multiple TLVs (excluding types 16/17 which require AFI/SAFI structure)
	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{InformationType: 0, InformationLength: 4, Information: make([]byte, 4)},   // Type 0
			{InformationType: 1, InformationLength: 4, Information: make([]byte, 4)},   // Type 1 (existing)
			{InformationType: 7, InformationLength: 8, Information: make([]byte, 8)},   // Type 7 (existing)
			{InformationType: 14, InformationLength: 8, Information: make([]byte, 8)},  // Type 14
			{InformationType: 15, InformationLength: 8, Information: make([]byte, 8)},  // Type 15
		},
	}

	// Set test values
	binary.BigEndian.PutUint32(statsMsg.StatsTLV[0].Information, 100)  // Type 0
	binary.BigEndian.PutUint32(statsMsg.StatsTLV[1].Information, 200)  // Type 1
	binary.BigEndian.PutUint64(statsMsg.StatsTLV[2].Information, 300)  // Type 7
	binary.BigEndian.PutUint64(statsMsg.StatsTLV[3].Information, 400)  // Type 14
	binary.BigEndian.PutUint64(statsMsg.StatsTLV[4].Information, 500)  // Type 15

	msg := bmp.Message{
		PeerHeader: &bmp.PerPeerHeader{
			PeerAS:   65001,
			PeerType: 0,
		},
		Payload: statsMsg,
	}

	m := Stats{
		RemoteASN:  msg.PeerHeader.PeerAS,
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
	}

	// Process all TLVs
	for _, tlv := range statsMsg.StatsTLV {
		switch tlv.InformationType {
		case 0:
			m.PrefixesRejectedInbound = binary.BigEndian.Uint32(tlv.Information)
		case 1:
			m.DuplicatePrefixs = binary.BigEndian.Uint32(tlv.Information)
		case 7:
			m.AdjRIBsIn = binary.BigEndian.Uint64(tlv.Information)
		case 14:
			m.PrePolicyAdjRIBOut = binary.BigEndian.Uint64(tlv.Information)
		case 15:
			m.PostPolicyAdjRIBOut = binary.BigEndian.Uint64(tlv.Information)
		}
	}

	// Verify all values (types 16/17 tested separately in bmpstats_rfc_test.go with AFI/SAFI structure)
	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"PrefixesRejectedInbound", m.PrefixesRejectedInbound, uint32(100)},
		{"DuplicatePrefixs", m.DuplicatePrefixs, uint32(200)},
		{"AdjRIBsIn", m.AdjRIBsIn, uint64(300)},
		{"PrePolicyAdjRIBOut", m.PrePolicyAdjRIBOut, uint64(400)},
		{"PostPolicyAdjRIBOut", m.PostPolicyAdjRIBOut, uint64(500)},
	}

	for _, tt := range tests {
		if tt.got != tt.expected {
			t.Errorf("%s: expected %v, got %v", tt.name, tt.expected, tt.got)
		}
	}
}

// TestStatsDataTypes verifies RFC 7854 compliant data types
func TestStatsDataTypes(t *testing.T) {
	// RFC 7854 Section 4.8:
	// - Type 0: 4-byte Gauge32 (uint32)
	// - Types 14-17: 8-byte Gauge64 (uint64)

	tests := []struct {
		name       string
		statType   uint16
		dataSize   int
		isGauge64  bool
	}{
		{"Type 0 - Prefixes Rejected", 0, 4, false},
		{"Type 14 - Pre-policy Adj-RIB-Out", 14, 8, true},
		{"Type 15 - Post-policy Adj-RIB-Out", 15, 8, true},
		{"Type 16 - Pre-policy Adj-RIB-Out Per-AFI", 16, 8, true},
		{"Type 17 - Post-policy Adj-RIB-Out Per-AFI", 17, 8, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.isGauge64 && tt.dataSize != 8 {
				t.Errorf("Type %d should use 8-byte Gauge64, got %d bytes", tt.statType, tt.dataSize)
			}
			if !tt.isGauge64 && tt.dataSize != 4 {
				t.Errorf("Type %d should use 4-byte Gauge32, got %d bytes", tt.statType, tt.dataSize)
			}
		})
	}
}
