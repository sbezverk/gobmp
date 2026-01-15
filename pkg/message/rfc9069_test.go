package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// RFC 9069 Compliance Tests
// RFC 9069: Support for Local RIB in the BGP Monitoring Protocol (BMP)
//
// Key requirements tested:
// - Section 4.3: Informational TLV Type 3 (VRF/Table Name) MUST be included for LocRIB peers
// - Section 4: PeerType 3 indicates Local RIB
// - TableName field must be populated for LocRIB peers from Informational TLV Type 3

// TestRFC9069_TableNameForLocRIBPeers verifies TableName is set correctly for LocRIB peers
// Per RFC 9069 Section 4.3: The Information field contains a UTF-8 string
// whose value MUST be equal to the value of the VRF name
func TestRFC9069_TableNameForLocRIBPeers(t *testing.T) {
	tests := []struct {
		name         string
		peerType     bmp.PeerType
		tableName    string
		expectSet    bool
		description  string
	}{
		{
			name:        "LocRIB peer with VRF name",
			peerType:    bmp.PeerType3, // LocRIB
			tableName:   "VRF-CUSTOMER-A",
			expectSet:   true,
			description: "RFC 9069 Section 4.3: TableName MUST be set for LocRIB peers",
		},
		{
			name:        "LocRIB peer with global table",
			peerType:    bmp.PeerType3,
			tableName:   "default",
			expectSet:   true,
			description: "RFC 9069: Global RIB should use 'default' or similar",
		},
		{
			name:        "Global Instance peer (PeerType0)",
			peerType:    bmp.PeerType0,
			tableName:   "",
			expectSet:   false,
			description: "RFC 9069: TableName not applicable for non-LocRIB peers",
		},
		{
			name:        "RD Instance peer (PeerType1)",
			peerType:    bmp.PeerType1,
			tableName:   "",
			expectSet:   false,
			description: "RFC 9069: TableName not applicable for non-LocRIB peers",
		},
		{
			name:        "Local Instance peer (PeerType2)",
			peerType:    bmp.PeerType2,
			tableName:   "",
			expectSet:   false,
			description: "RFC 9069: TableName not applicable for non-LocRIB peers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockPub := &mockPublisher{}
			p := NewProducer(mockPub, false).(*producer)

			// Setup table properties with TableName TLV for LocRIB peers
			if tt.peerType == bmp.PeerType3 && tt.tableName != "" {
				tableKey := "10.0.0.10:0"
				p.tableLock.Lock()
				p.tableProperties[tableKey] = PerTableProperties{
					addPathCapable: make(map[int]bool),
					tableInfoTLVs: []bmp.InformationalTLV{
						{
							InformationType: 3, // Table Name TLV
							Information:     []byte(tt.tableName),
						},
					},
				}
				p.tableLock.Unlock()
			}

			// Verify GetTableName returns expected value
			got := p.GetTableName("10.0.0.1", "0:0")
			if tt.expectSet && got != tt.tableName {
				t.Errorf("%s: GetTableName() = %q, want %q", tt.description, got, tt.tableName)
			}
			if !tt.expectSet && got != "" {
				t.Errorf("%s: GetTableName() = %q, want empty", tt.description, got)
			}
		})
	}
}

// TestRFC9069_PeerTypeDetection verifies correct identification of LocRIB peers
// Per RFC 9069 Section 4: Peer Type = 3 indicates the information is about the local-RIB
// Note: IsLocRIB() returns error for non-PeerType3 (by design - only valid for LocRIB peers)
func TestRFC9069_PeerTypeDetection(t *testing.T) {
	tests := []struct {
		name        string
		peerType    bmp.PeerType
		expectError bool // IsLocRIB returns error for non-PeerType3
		isLocRIB    bool
	}{
		{
			name:        "PeerType 0 - Global Instance Peer",
			peerType:    bmp.PeerType0,
			expectError: true, // Not a LocRIB peer
			isLocRIB:    false,
		},
		{
			name:        "PeerType 1 - RD Instance Peer",
			peerType:    bmp.PeerType1,
			expectError: true, // Not a LocRIB peer
			isLocRIB:    false,
		},
		{
			name:        "PeerType 2 - Local Instance Peer",
			peerType:    bmp.PeerType2,
			expectError: true, // Not a LocRIB peer
			isLocRIB:    false,
		},
		{
			name:        "PeerType 3 - Loc-RIB Instance Peer",
			peerType:    bmp.PeerType3,
			expectError: false,
			isLocRIB:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := &bmp.PerPeerHeader{
				PeerType:          tt.peerType,
				PeerBGPID:         []byte{10, 0, 0, 1},
				PeerDistinguisher: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			}

			isLocRIB, err := ph.IsLocRIB()

			if tt.expectError {
				// Non-LocRIB peers should return error
				if err == nil {
					t.Errorf("IsLocRIB() should return error for PeerType %d", tt.peerType)
				}
				return
			}

			if err != nil {
				t.Fatalf("IsLocRIB() returned error: %v", err)
			}

			if isLocRIB != tt.isLocRIB {
				t.Errorf("IsLocRIB() = %v, want %v for PeerType %d", isLocRIB, tt.isLocRIB, tt.peerType)
			}
		})
	}
}

// TestRFC9069_InformationalTLVType3 verifies correct parsing of Table Name TLV
// Per RFC 9069 Section 4.3: Informational TLV Type 3 carries VRF/Table name
func TestRFC9069_InformationalTLVType3(t *testing.T) {
	tests := []struct {
		name      string
		tlvs      []bmp.InformationalTLV
		expected  string
	}{
		{
			name: "Single Table Name TLV",
			tlvs: []bmp.InformationalTLV{
				{InformationType: 3, Information: []byte("VRF-CUSTOMER-A")},
			},
			expected: "VRF-CUSTOMER-A",
		},
		{
			name: "Multiple TLVs with Table Name",
			tlvs: []bmp.InformationalTLV{
				{InformationType: 0, Information: []byte("String info")},
				{InformationType: 1, Information: []byte("SysDescr")},
				{InformationType: 3, Information: []byte("VRF-INTERNET")},
				{InformationType: 2, Information: []byte("SysName")},
			},
			expected: "VRF-INTERNET",
		},
		{
			name: "No Table Name TLV",
			tlvs: []bmp.InformationalTLV{
				{InformationType: 0, Information: []byte("String info")},
				{InformationType: 1, Information: []byte("SysDescr")},
			},
			expected: "",
		},
		{
			name:     "Empty TLV list",
			tlvs:     []bmp.InformationalTLV{},
			expected: "",
		},
		{
			name: "Unicode VRF name",
			tlvs: []bmp.InformationalTLV{
				{InformationType: 3, Information: []byte("VRF-客户-A")},
			},
			expected: "VRF-客户-A",
		},
		{
			name: "Long VRF name",
			tlvs: []bmp.InformationalTLV{
				{InformationType: 3, Information: []byte("VRF-VERY-LONG-NAME-FOR-CUSTOMER-NETWORK-SEGMENT-001")},
			},
			expected: "VRF-VERY-LONG-NAME-FOR-CUSTOMER-NETWORK-SEGMENT-001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockPub := &mockPublisher{}
			p := NewProducer(mockPub, false).(*producer)

			tableKey := "10.0.0.10:0"
			p.tableLock.Lock()
			p.tableProperties[tableKey] = PerTableProperties{
				addPathCapable: make(map[int]bool),
				tableInfoTLVs:  tt.tlvs,
			}
			p.tableLock.Unlock()

			got := p.GetTableName("10.0.0.1", "0:0")
			if got != tt.expected {
				t.Errorf("GetTableName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// Note: RIB flag tests (IsLocRIBFiltered, IsAdjRIBInPost, etc.) are in pkg/bmp/per-peer-header_test.go
// Those tests can access private flag fields. This file tests TableName functionality.

// TestRFC9069_MultiVRFTableNames verifies correct TableName handling across multiple VRFs
// Per RFC 9069: Each VRF has its own unique TableName
func TestRFC9069_MultiVRFTableNames(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	// Setup multiple VRF tables
	vrfs := []struct {
		bgpID     string
		rd        string
		tableName string
	}{
		{"10.0.0.1", "0:0", "default"},
		{"10.0.0.1", "65000:100", "VRF-CUSTOMER-A"},
		{"10.0.0.1", "65000:200", "VRF-CUSTOMER-B"},
		{"192.168.1.1", "65000:100", "VRF-INTERNET"},
	}

	// Create all VRF table entries
	p.tableLock.Lock()
	for _, vrf := range vrfs {
		tableKey := vrf.bgpID + vrf.rd
		p.tableProperties[tableKey] = PerTableProperties{
			addPathCapable: make(map[int]bool),
			tableInfoTLVs: []bmp.InformationalTLV{
				{InformationType: 3, Information: []byte(vrf.tableName)},
			},
		}
	}
	p.tableLock.Unlock()

	// Verify each VRF returns correct TableName
	for _, vrf := range vrfs {
		t.Run(vrf.tableName, func(t *testing.T) {
			got := p.GetTableName(vrf.bgpID, vrf.rd)
			if got != vrf.tableName {
				t.Errorf("GetTableName(%s, %s) = %q, want %q", vrf.bgpID, vrf.rd, got, vrf.tableName)
			}
		})
	}
}
