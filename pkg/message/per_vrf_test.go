package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestGetTableKey verifies table key generation
// Per RFC 9069 Section 4: Table key = BGP-ID + Peer Distinguisher
func TestGetTableKey(t *testing.T) {
	tests := []struct {
		name     string
		peerType bmp.PeerType
		bgpID    []byte
		rd       []byte
		expected string
	}{
		{
			name:     "IPv4 no RD (PeerType0)",
			peerType: bmp.PeerType0,
			bgpID:    []byte{10, 0, 0, 1},
			rd:       []byte{0, 0, 0, 0, 0, 0, 0, 0},
			expected: "10.0.0.10:0",
		},
		{
			name:     "IPv4 with RD Type 1 (PeerType1)",
			peerType: bmp.PeerType1,
			bgpID:    []byte{192, 168, 1, 1},
			rd:       []byte{0, 1, 192, 168, 1, 1, 0, 100}, // Type 1: IP:ASN
			expected: "192.168.1.1192.168.1.1:100",
		},
		{
			name:     "LocRIB with RD Type 0 (PeerType3)",
			peerType: bmp.PeerType3,
			bgpID:    []byte{10, 0, 0, 1},
			rd:       []byte{0, 0, 0, 100, 0, 0, 0, 200}, // Type 0: ASN:NN -> 100:200
			expected: "10.0.0.1:00000064000000c8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := &bmp.PerPeerHeader{
				PeerType:          tt.peerType,
				PeerBGPID:         tt.bgpID,
				PeerDistinguisher: tt.rd,
			}

			got := ph.GetTableKey()
			if got != tt.expected {
				t.Errorf("GetTableKey() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestGetTableName verifies table name extraction from TLVs.
func TestGetTableName(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	tests := []struct {
		name     string
		bgpID    []byte
		rd       []byte
		tlvs     []bmp.InformationalTLV
		expected string
	}{
		{
			name:  "Single table name TLV",
			bgpID: []byte{10, 0, 0, 1},
			rd:    make([]byte, 8),
			tlvs: []bmp.InformationalTLV{
				{InformationType: 3, Information: []byte("VRF-CUSTOMER-A")},
			},
			expected: "VRF-CUSTOMER-A",
		},
		{
			name:  "Multiple TLVs including table name",
			bgpID: []byte{192, 168, 1, 1},
			rd:    []byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 100},
			tlvs: []bmp.InformationalTLV{
				{InformationType: 1, Information: []byte("String TLV")},
				{InformationType: 3, Information: []byte("VRF-INTERNET")},
				{InformationType: 2, Information: []byte("SysDescr")},
			},
			expected: "VRF-INTERNET",
		},
		{
			name:     "No table name TLV",
			bgpID:    []byte{10, 0, 0, 1},
			rd:       make([]byte, 8),
			tlvs:     []bmp.InformationalTLV{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := &bmp.PerPeerHeader{PeerType: bmp.PeerType3, PeerBGPID: tt.bgpID, PeerDistinguisher: tt.rd}
			tableKey := ph.GetTableKey()

			p.tableLock.Lock()
			p.tableProperties[tableKey] = PerTableProperties{
				tableInfoTLVs: tt.tlvs,
			}
			p.tableLock.Unlock()

			got := p.getTableName(ph)
			if got != tt.expected {
				t.Errorf("GetTableName() = %v, want %v", got, tt.expected)
			}
		})
	}
	if got := p.getTableName(nil); got != "" {
		t.Errorf("nil peer table name = %q, want empty", got)
	}
}

// Note: mockPublisher already defined in bmpstats_test.go, reusing it
