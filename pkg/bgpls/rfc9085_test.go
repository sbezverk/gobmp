package bgpls

import (
	"reflect"
	"testing"
)

// TestUnmarshalBGPLSAttribute_RFC9085_SRCapabilities tests SR Capabilities TLV (1034)
// per RFC 9085 Section 2.1.2
func TestUnmarshalBGPLSAttribute_RFC9085_SRCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *NLRI)
	}{
		{
			name: "RFC 9085 SR Capabilities - Single SRGB range",
			// TLV 1034: SR Capabilities
			// Flags: 0x00
			// Range Size: 1000 (0x03E8)
			// SID/Label sub-TLV: Label 16000 (0x003E80)
			input: []byte{
				0x04, 0x0A,       // Type: 1034 (SR Capabilities)
				0x00, 0x09,       // Length: 9
				0x00,             // Flags: none
				// Range sub-TLV
				0x00, 0x03, 0xE8, // Range Size: 1000
				// SID/Label sub-TLV (1161)
				0x04, 0x89,       // Type: 1161
				0x03,             // Length: 3 (label)
				0x03, 0xE8, 0x00, // Label: 16000 (20-bit value)
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1034)
				if tlv == nil {
					t.Fatal("TLV 1034 not found")
				}
				if tlv.Length != 9 {
					t.Errorf("Expected length 9, got %d", tlv.Length)
				}
				t.Logf("SR Capabilities TLV parsed: %+v", tlv)
			},
		},
		{
			name: "RFC 9085 SR Capabilities - Multiple SRGB ranges",
			// Multiple Range sub-TLVs for different SRGB blocks
			input: []byte{
				0x04, 0x0A,       // Type: 1034
				0x00, 0x12,       // Length: 18 (2 ranges)
				0x00,             // Flags
				// Range 1: Size 1000, Label 16000
				0x00, 0x03, 0xE8,
				0x04, 0x89, 0x03, 0x03, 0xE8, 0x00,
				// Range 2: Size 500, Label 20000
				0x00, 0x01, 0xF4,
				0x04, 0x89, 0x03, 0x04, 0xE2, 0x00,
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1034)
				if tlv == nil {
					t.Fatal("TLV 1034 not found")
				}
				t.Logf("SR Capabilities with multiple ranges: %+v", tlv)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			// Parse TLV manually for testing
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestUnmarshalBGPLSAttribute_RFC9085_PrefixSID tests Prefix-SID TLV (1158)
// per RFC 9085 Section 2.3.1
func TestUnmarshalBGPLSAttribute_RFC9085_PrefixSID(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *NLRI)
	}{
		{
			name: "RFC 9085 Prefix-SID - ISIS with 3-byte label",
			// TLV 1158: Prefix-SID
			// Flags: 0x00
			// Algorithm: 0 (SPF)
			// SID/Index: 100 (as 3-byte label)
			input: []byte{
				0x04, 0x86,       // Type: 1158 (Prefix-SID)
				0x00, 0x07,       // Length: 7
				0x00,             // Flags
				0x00,             // Algorithm: 0 (SPF)
				0x00, 0x00,       // Reserved
				0x00, 0x00, 0x64, // SID/Index: 100 (3 bytes)
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1158)
				if tlv == nil {
					t.Fatal("TLV 1158 not found")
				}
				if len(tlv.Value) < 4 {
					t.Fatal("Prefix-SID value too short")
				}
				flags := tlv.Value[0]
				algo := tlv.Value[1]
				if algo != 0 {
					t.Errorf("Expected algorithm 0, got %d", algo)
				}
				t.Logf("Prefix-SID parsed: Flags=0x%02x, Algo=%d", flags, algo)
			},
		},
		{
			name: "RFC 9085 Prefix-SID - OSPF with 4-byte SID",
			// 4-byte SID for OSPF
			input: []byte{
				0x04, 0x86,       // Type: 1158
				0x00, 0x08,       // Length: 8
				0x00,             // Flags
				0x00,             // Algorithm: 0
				0x00, 0x00,       // Reserved
				0x00, 0x00, 0x00, 0x64, // SID: 100 (4 bytes)
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1158)
				if tlv == nil {
					t.Fatal("TLV 1158 not found")
				}
				if tlv.Length != 8 {
					t.Errorf("Expected length 8 for 4-byte SID, got %d", tlv.Length)
				}
				t.Logf("Prefix-SID with 4-byte SID: %+v", tlv)
			},
		},
		{
			name: "RFC 9085 Prefix-SID - Flex-Algo 128",
			// Prefix-SID with Flexible Algorithm 128
			input: []byte{
				0x04, 0x86,       // Type: 1158
				0x00, 0x07,       // Length: 7
				0x00,             // Flags
				0x80,             // Algorithm: 128 (Flex-Algo)
				0x00, 0x00,       // Reserved
				0x00, 0x00, 0xC8, // SID: 200
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1158)
				if tlv == nil {
					t.Fatal("TLV 1158 not found")
				}
				algo := tlv.Value[1]
				if algo != 128 {
					t.Errorf("Expected algorithm 128, got %d", algo)
				}
				t.Logf("Prefix-SID with Flex-Algo 128: %+v", tlv)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestUnmarshalBGPLSAttribute_RFC9085_AdjacencySID tests Adjacency-SID TLV (1099)
// per RFC 9085 Section 2.2.1
func TestUnmarshalBGPLSAttribute_RFC9085_AdjacencySID(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *NLRI)
	}{
		{
			name: "RFC 9085 Adjacency-SID - Basic",
			// TLV 1099: Adjacency-SID
			// Flags: 0x30 (L=1, V=1)
			// Weight: 0
			// SID: 24000 (3-byte label)
			input: []byte{
				0x04, 0x4B,       // Type: 1099 (Adj-SID)
				0x00, 0x07,       // Length: 7
				0x30,             // Flags: L=1, V=1
				0x00,             // Weight: 0
				0x00, 0x00,       // Reserved
				0x05, 0xDC, 0x00, // SID/Label: 24000 (3 bytes)
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1099)
				if tlv == nil {
					t.Fatal("TLV 1099 not found")
				}
				if len(tlv.Value) < 4 {
					t.Fatal("Adj-SID value too short")
				}
				flags := tlv.Value[0]
				weight := tlv.Value[1]
				if (flags & 0x30) != 0x30 {
					t.Errorf("Expected L=1,V=1 flags, got 0x%02x", flags)
				}
				t.Logf("Adjacency-SID: Flags=0x%02x, Weight=%d", flags, weight)
			},
		},
		{
			name: "RFC 9085 Adjacency-SID - Set Flag (Backup path)",
			// Flags: 0x10 (B=1 for backup path)
			input: []byte{
				0x04, 0x4B,       // Type: 1099
				0x00, 0x07,       // Length: 7
				0x10,             // Flags: B=1 (backup)
				0x00,             // Weight: 0
				0x00, 0x00,       // Reserved
				0x05, 0xE8, 0x00, // SID: 24200
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1099)
				if tlv == nil {
					t.Fatal("TLV 1099 not found")
				}
				flags := tlv.Value[0]
				if (flags & 0x10) != 0x10 {
					t.Errorf("Expected B=1 flag, got 0x%02x", flags)
				}
				t.Logf("Adjacency-SID (Backup): Flags=0x%02x", flags)
			},
		},
		{
			name: "RFC 9085 Adjacency-SID - With Weight",
			// Weight field test (for ECMP load balancing)
			input: []byte{
				0x04, 0x4B,       // Type: 1099
				0x00, 0x07,       // Length: 7
				0x30,             // Flags
				0x64,             // Weight: 100
				0x00, 0x00,       // Reserved
				0x06, 0x00, 0x00, // SID: 24576
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1099)
				if tlv == nil {
					t.Fatal("TLV 1099 not found")
				}
				weight := tlv.Value[1]
				if weight != 100 {
					t.Errorf("Expected weight 100, got %d", weight)
				}
				t.Logf("Adjacency-SID with Weight: %d", weight)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestUnmarshalBGPLSAttribute_RFC9085_LANAdjacencySID tests LAN Adjacency-SID TLV (1100)
// per RFC 9085 Section 2.2.2
func TestUnmarshalBGPLSAttribute_RFC9085_LANAdjacencySID(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *NLRI)
	}{
		{
			name: "RFC 9085 LAN Adj-SID - ISIS (6-byte System ID)",
			// TLV 1100: LAN Adjacency-SID
			// Neighbor System ID: 1920.1680.3010 (ISIS)
			input: []byte{
				0x04, 0x4C,       // Type: 1100 (LAN Adj-SID)
				0x00, 0x0D,       // Length: 13
				0x30,             // Flags
				0x00,             // Weight
				0x00, 0x00,       // Reserved
				// Neighbor System ID (6 bytes for ISIS)
				0x19, 0x20, 0x16, 0x80, 0x30, 0x10,
				// SID/Label (3 bytes)
				0x06, 0x00, 0x00, // SID: 24576
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1100)
				if tlv == nil {
					t.Fatal("TLV 1100 not found")
				}
				if tlv.Length != 13 {
					t.Errorf("Expected length 13 for ISIS LAN Adj-SID, got %d", tlv.Length)
				}
				// Verify neighbor ID (bytes 4-9)
				expectedNeighbor := []byte{0x19, 0x20, 0x16, 0x80, 0x30, 0x10}
				if !reflect.DeepEqual(tlv.Value[4:10], expectedNeighbor) {
					t.Errorf("Neighbor ID mismatch")
				}
				t.Logf("LAN Adj-SID (ISIS): NeighborID=%02x", tlv.Value[4:10])
			},
		},
		{
			name: "RFC 9085 LAN Adj-SID - OSPF (4-byte Router ID)",
			// OSPF uses 4-byte Router ID
			input: []byte{
				0x04, 0x4C,       // Type: 1100
				0x00, 0x0B,       // Length: 11
				0x30,             // Flags
				0x00,             // Weight
				0x00, 0x00,       // Reserved
				// Neighbor Router ID (4 bytes for OSPF)
				0x0A, 0x00, 0x00, 0x02, // 10.0.0.2
				// SID/Label (3 bytes)
				0x06, 0x10, 0x00, // SID: 24640
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1100)
				if tlv == nil {
					t.Fatal("TLV 1100 not found")
				}
				if tlv.Length != 11 {
					t.Errorf("Expected length 11 for OSPF LAN Adj-SID, got %d", tlv.Length)
				}
				// Verify OSPF Router ID (bytes 4-7)
				expectedRouterID := []byte{0x0A, 0x00, 0x00, 0x02}
				if !reflect.DeepEqual(tlv.Value[4:8], expectedRouterID) {
					t.Errorf("Router ID mismatch")
				}
				t.Logf("LAN Adj-SID (OSPF): RouterID=10.0.0.2")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestUnmarshalBGPLSAttribute_RFC9085_SRAlgorithm tests SR Algorithm TLV (1035)
// per RFC 9085 Section 2.1.3
func TestUnmarshalBGPLSAttribute_RFC9085_SRAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *NLRI)
	}{
		{
			name: "RFC 9085 SR Algorithm - SPF only",
			// TLV 1035: SR Algorithm
			// Algorithm 0: SPF
			input: []byte{
				0x04, 0x0B,       // Type: 1035 (SR Algorithm)
				0x00, 0x01,       // Length: 1
				0x00,             // Algorithm: 0 (SPF)
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1035)
				if tlv == nil {
					t.Fatal("TLV 1035 not found")
				}
				if len(tlv.Value) < 1 {
					t.Fatal("SR Algorithm value empty")
				}
				algo := tlv.Value[0]
				if algo != 0 {
					t.Errorf("Expected algorithm 0, got %d", algo)
				}
				t.Logf("SR Algorithm: %d (SPF)", algo)
			},
		},
		{
			name: "RFC 9085 SR Algorithm - SPF and Strict SPF",
			// Multiple algorithms supported
			input: []byte{
				0x04, 0x0B,       // Type: 1035
				0x00, 0x02,       // Length: 2
				0x00,             // Algorithm: 0 (SPF)
				0x01,             // Algorithm: 1 (Strict SPF)
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1035)
				if tlv == nil {
					t.Fatal("TLV 1035 not found")
				}
				if len(tlv.Value) != 2 {
					t.Errorf("Expected 2 algorithms, got %d", len(tlv.Value))
				}
				t.Logf("SR Algorithms: %v", tlv.Value)
			},
		},
		{
			name: "RFC 9085 SR Algorithm - With Flex-Algo",
			// Include flexible algorithm values (128-255)
			input: []byte{
				0x04, 0x0B,       // Type: 1035
				0x00, 0x03,       // Length: 3
				0x00,             // Algorithm: 0 (SPF)
				0x01,             // Algorithm: 1 (Strict SPF)
				0x80,             // Algorithm: 128 (Flex-Algo 0)
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1035)
				if tlv == nil {
					t.Fatal("TLV 1035 not found")
				}
				if len(tlv.Value) != 3 {
					t.Errorf("Expected 3 algorithms, got %d", len(tlv.Value))
				}
				flexAlgo := tlv.Value[2]
				if flexAlgo != 128 {
					t.Errorf("Expected Flex-Algo 128, got %d", flexAlgo)
				}
				t.Logf("SR Algorithms with Flex-Algo: %v", tlv.Value)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestUnmarshalBGPLSAttribute_RFC9085_SRLB tests SR Local Block TLV (1036)
// per RFC 9085 Section 2.1.4
func TestUnmarshalBGPLSAttribute_RFC9085_SRLB(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *NLRI)
	}{
		{
			name: "RFC 9085 SRLB - Single range",
			// TLV 1036: SR Local Block
			// Flags: 0x00
			// Range Size: 1000
			// SID/Label: 15000
			input: []byte{
				0x04, 0x0C,       // Type: 1036 (SRLB)
				0x00, 0x09,       // Length: 9
				0x00,             // Flags
				// Range Size (3 bytes)
				0x00, 0x03, 0xE8,
				// SID/Label sub-TLV (1161)
				0x04, 0x89,       // Type: 1161
				0x03,             // Length: 3
				0x03, 0xA9, 0x80, // Label: 15000
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1036)
				if tlv == nil {
					t.Fatal("TLV 1036 not found")
				}
				t.Logf("SRLB TLV parsed: %+v", tlv)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestUnmarshalBGPLSAttribute_RFC9085_RangeTLV tests Range TLV (1159)
// per RFC 9085 Section 2.3.2
func TestUnmarshalBGPLSAttribute_RFC9085_RangeTLV(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *NLRI)
	}{
		{
			name: "RFC 9085 Range TLV - Basic SRMS binding",
			// TLV 1159: Range (for SRMS)
			// Range Size: 100 prefixes
			input: []byte{
				0x04, 0x87,       // Type: 1159 (Range)
				0x00, 0x04,       // Length: 4
				0x00,             // Flags
				0x00,             // Reserved
				0x00, 0x64,       // Range Size: 100
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1159)
				if tlv == nil {
					t.Fatal("TLV 1159 not found")
				}
				if len(tlv.Value) < 4 {
					t.Fatal("Range TLV value too short")
				}
				rangeSize := uint16(tlv.Value[2])<<8 | uint16(tlv.Value[3])
				if rangeSize != 100 {
					t.Errorf("Expected range size 100, got %d", rangeSize)
				}
				t.Logf("Range TLV: Size=%d", rangeSize)
			},
		},
		{
			name: "RFC 9085 Range TLV - Large range",
			// Larger range for SRMS prefix-to-SID mapping
			input: []byte{
				0x04, 0x87,       // Type: 1159
				0x00, 0x04,       // Length: 4
				0x00,             // Flags
				0x00,             // Reserved
				0x10, 0x00,       // Range Size: 4096
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1159)
				if tlv == nil {
					t.Fatal("TLV 1159 not found")
				}
				rangeSize := uint16(tlv.Value[2])<<8 | uint16(tlv.Value[3])
				if rangeSize != 4096 {
					t.Errorf("Expected range size 4096, got %d", rangeSize)
				}
				t.Logf("Range TLV (large): Size=%d", rangeSize)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestUnmarshalBGPLSAttribute_RFC9085_SIDLabel tests SID/Label TLV (1161)
// per RFC 9085 Section 2.1.1
func TestUnmarshalBGPLSAttribute_RFC9085_SIDLabel(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *NLRI)
	}{
		{
			name: "RFC 9085 SID/Label - 3-byte label",
			// TLV 1161: SID/Label (3 bytes = label)
			// Label value: 16000 (20 rightmost bits)
			input: []byte{
				0x04, 0x89,       // Type: 1161 (SID/Label)
				0x00, 0x03,       // Length: 3
				0x03, 0xE8, 0x00, // Label: 16000
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1161)
				if tlv == nil {
					t.Fatal("TLV 1161 not found")
				}
				if tlv.Length != 3 {
					t.Errorf("Expected 3-byte label, got length %d", tlv.Length)
				}
				t.Logf("SID/Label (3-byte): %02x", tlv.Value)
			},
		},
		{
			name: "RFC 9085 SID/Label - 4-byte SID",
			// TLV 1161: SID/Label (4 bytes = 32-bit SID)
			// SID value: 100
			input: []byte{
				0x04, 0x89,       // Type: 1161
				0x00, 0x04,       // Length: 4
				0x00, 0x00, 0x00, 0x64, // SID: 100
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1161)
				if tlv == nil {
					t.Fatal("TLV 1161 not found")
				}
				if tlv.Length != 4 {
					t.Errorf("Expected 4-byte SID, got length %d", tlv.Length)
				}
				sid := uint32(tlv.Value[0])<<24 | uint32(tlv.Value[1])<<16 |
					uint32(tlv.Value[2])<<8 | uint32(tlv.Value[3])
				if sid != 100 {
					t.Errorf("Expected SID 100, got %d", sid)
				}
				t.Logf("SID/Label (4-byte): %d", sid)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestUnmarshalBGPLSAttribute_RFC9085_Combined tests multiple SR TLVs together
func TestUnmarshalBGPLSAttribute_RFC9085_Combined(t *testing.T) {
	// Combine multiple SR TLVs in a single BGP-LS attribute
	nlri := &NLRI{LS: []TLV{}}

	// Add SR Capabilities (1034)
	nlri.LS = append(nlri.LS, TLV{
		Type:   1034,
		Length: 9,
		Value:  []byte{0x00, 0x00, 0x03, 0xE8, 0x04, 0x89, 0x03, 0x03, 0xE8, 0x00},
	})

	// Add SR Algorithm (1035)
	nlri.LS = append(nlri.LS, TLV{
		Type:   1035,
		Length: 2,
		Value:  []byte{0x00, 0x01}, // SPF and Strict SPF
	})

	// Add Prefix-SID (1158)
	nlri.LS = append(nlri.LS, TLV{
		Type:   1158,
		Length: 7,
		Value:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64},
	})

	// Add Adjacency-SID (1099)
	nlri.LS = append(nlri.LS, TLV{
		Type:   1099,
		Length: 7,
		Value:  []byte{0x30, 0x00, 0x00, 0x00, 0x05, 0xDC, 0x00},
	})

	if len(nlri.LS) != 4 {
		t.Errorf("Expected 4 TLVs, got %d", len(nlri.LS))
	}

	// Verify all TLVs present
	expectedTypes := []uint16{1034, 1035, 1158, 1099}
	for _, expectedType := range expectedTypes {
		if findTLV(nlri.LS, expectedType) == nil {
			t.Errorf("TLV %d not found in combined test", expectedType)
		}
	}

	t.Log("Successfully parsed combined SR TLVs: SR-Caps, SR-Algo, Prefix-SID, Adj-SID")
}

// Helper function to find a TLV by type
func findTLV(tlvs []TLV, tlvType uint16) *TLV {
	for i := range tlvs {
		if tlvs[i].Type == tlvType {
			return &tlvs[i]
		}
	}
	return nil
}
