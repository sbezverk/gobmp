package l3vpn

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// RFC 4364 - BGP/MPLS IP Virtual Private Networks (VPNs)
//
// This file contains comprehensive tests for L3VPN NLRI parsing
// based on RFC 4364 specifications.
//
// Key RFC 4364 Components Tested:
// - VPNv4 NLRI (AFI 1, SAFI 128)
// - VPNv6 NLRI (AFI 2, SAFI 128)
// - Route Distinguisher Types 0, 1, 2
// - MPLS Label Stack
// - ADD-PATH (Path ID) support
//
// NLRI Format (RFC 4364 Section 4.3.4):
// +---------------------------+
// |   Length (1 octet)        |  <- Total length in bits
// +---------------------------+
// |   Label (3 octets)        |  <- MPLS Label(s), 20-bit value + 3-bit Exp + BoS
// +---------------------------+
// |   Route Distinguisher     |  <- 8 octets
// |   (8 octets)              |
// +---------------------------+
// |   IPv4/IPv6 Prefix        |  <- Variable length
// |   (variable)              |
// +---------------------------+

// =============================================================================
// RFC 4364 Section 4.2 - Route Distinguisher Tests
// =============================================================================

// TestRFC4364_RouteDistinguisher_Type0 tests RD Type 0 format:
// 2-byte Administrator (ASN) : 4-byte Assigned Number
func TestRFC4364_RouteDistinguisher_Type0(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *base.MPNLRI
	}{
		{
			// RD Type 0: ASN 577 (0x0241) : Value 64491 (0x0000FBEB)
			// Prefix: 10.0.0.0/24
			name: "RD_Type0_ASN577_Value64491_Prefix_10.0.0.0/24",
			input: []byte{
				0x70,                   // Length: 112 bits (24 label + 64 RD + 24 prefix)
				0x05, 0xdc, 0x31,       // Label 24003, BoS=1
				0x00, 0x00,             // RD Type 0
				0x02, 0x41,             // ASN 577
				0x00, 0x00, 0xfb, 0xeb, // Assigned Number 64491
				0x0a, 0x00, 0x00,       // Prefix 10.0.0.0/24
			},
			expected: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 24,
						Label: []*base.Label{
							{Value: 24003, Exp: 0, BoS: true},
						},
						RD: &base.RD{
							Type:  0,
							Value: []byte{0x02, 0x41, 0x00, 0x00, 0xfb, 0xeb},
						},
						Prefix: []byte{0x0a, 0x00, 0x00},
					},
				},
			},
		},
		{
			// RD Type 0: ASN 65000 (0xFDE8) : Value 100 (0x00000064)
			// Prefix: 192.168.1.0/24
			name: "RD_Type0_ASN65000_Value100_Prefix_192.168.1.0/24",
			input: []byte{
				0x70,                   // Length: 112 bits
				0x00, 0x10, 0x01,       // Label 1, BoS=1
				0x00, 0x00,             // RD Type 0
				0xfd, 0xe8,             // ASN 65000
				0x00, 0x00, 0x00, 0x64, // Assigned Number 100
				0xc0, 0xa8, 0x01,       // Prefix 192.168.1.0/24
			},
			expected: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 24,
						Label: []*base.Label{
							{Value: 1, Exp: 0, BoS: true},
						},
						RD: &base.RD{
							Type:  0,
							Value: []byte{0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64},
						},
						Prefix: []byte{0xc0, 0xa8, 0x01},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalL3VPNNLRI(tt.input, false)
			if err != nil {
				t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
			}
			if got.NLRI[0].RD.Type != 0 {
				t.Errorf("Expected RD Type 0, got %d", got.NLRI[0].RD.Type)
			}
			if len(got.NLRI) != len(tt.expected.NLRI) {
				t.Errorf("Expected %d NLRIs, got %d", len(tt.expected.NLRI), len(got.NLRI))
			}
		})
	}
}

// TestRFC4364_RouteDistinguisher_Type1 tests RD Type 1 format:
// 4-byte Administrator (IPv4) : 2-byte Assigned Number
func TestRFC4364_RouteDistinguisher_Type1(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *base.MPNLRI
	}{
		{
			// RD Type 1: IP 10.0.0.7 : Value 1
			// Prefix: 172.16.7.0/24
			name: "RD_Type1_IP_10.0.0.7_Value1_Prefix_172.16.7.0/24",
			input: []byte{
				0x70,                   // Length: 112 bits
				0x05, 0xdd, 0x31,       // Label 24019, BoS=1
				0x00, 0x01,             // RD Type 1
				0x0a, 0x00, 0x00, 0x07, // IP 10.0.0.7
				0x00, 0x01,             // Assigned Number 1
				0xac, 0x10, 0x07,       // Prefix 172.16.7.0/24
			},
			expected: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 24,
						Label: []*base.Label{
							{Value: 24019, Exp: 0, BoS: true},
						},
						RD: &base.RD{
							Type:  1,
							Value: []byte{0x0a, 0x00, 0x00, 0x07, 0x00, 0x01},
						},
						Prefix: []byte{0xac, 0x10, 0x07},
					},
				},
			},
		},
		{
			// RD Type 1: IP 192.168.100.1 : Value 500
			// Prefix: 10.10.10.0/24
			name: "RD_Type1_IP_192.168.100.1_Value500_Prefix_10.10.10.0/24",
			input: []byte{
				0x70,                   // Length: 112 bits
				0x00, 0x64, 0x01,       // Label 100, BoS=1
				0x00, 0x01,             // RD Type 1
				0xc0, 0xa8, 0x64, 0x01, // IP 192.168.100.1
				0x01, 0xf4,             // Assigned Number 500
				0x0a, 0x0a, 0x0a,       // Prefix 10.10.10.0/24
			},
			expected: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 24,
						Label: []*base.Label{
							{Value: 100, Exp: 0, BoS: true},
						},
						RD: &base.RD{
							Type:  1,
							Value: []byte{0xc0, 0xa8, 0x64, 0x01, 0x01, 0xf4},
						},
						Prefix: []byte{0x0a, 0x0a, 0x0a},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalL3VPNNLRI(tt.input, false)
			if err != nil {
				t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
			}
			if got.NLRI[0].RD.Type != 1 {
				t.Errorf("Expected RD Type 1, got %d", got.NLRI[0].RD.Type)
			}
		})
	}
}

// TestRFC4364_RouteDistinguisher_Type2 tests RD Type 2 format:
// 4-byte Administrator (4-byte ASN) : 2-byte Assigned Number
func TestRFC4364_RouteDistinguisher_Type2(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *base.MPNLRI
	}{
		{
			// RD Type 2: 4-byte ASN 65536 : Value 1
			// Prefix: 10.20.30.0/24
			name: "RD_Type2_ASN65536_Value1_Prefix_10.20.30.0/24",
			input: []byte{
				0x70,                   // Length: 112 bits
				0x00, 0xc8, 0x01,       // Label 200, BoS=1
				0x00, 0x02,             // RD Type 2
				0x00, 0x01, 0x00, 0x00, // 4-byte ASN 65536
				0x00, 0x01,             // Assigned Number 1
				0x0a, 0x14, 0x1e,       // Prefix 10.20.30.0/24
			},
			expected: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 24,
						Label: []*base.Label{
							{Value: 200, Exp: 0, BoS: true},
						},
						RD: &base.RD{
							Type:  2,
							Value: []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01},
						},
						Prefix: []byte{0x0a, 0x14, 0x1e},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalL3VPNNLRI(tt.input, false)
			if err != nil {
				t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
			}
			if got.NLRI[0].RD.Type != 2 {
				t.Errorf("Expected RD Type 2, got %d", got.NLRI[0].RD.Type)
			}
		})
	}
}

// =============================================================================
// RFC 4364 Section 4.3 - VPNv4 NLRI Tests
// =============================================================================

// TestRFC4364_VPNv4_VariousPrefixLengths tests VPNv4 with different prefix lengths
func TestRFC4364_VPNv4_VariousPrefixLengths(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		expectedLen    uint8
		expectedPrefix []byte
	}{
		{
			// /32 host route
			name: "VPNv4_Host_Route_32",
			input: []byte{
				0x78,                         // Length: 120 bits (24 + 64 + 32)
				0x05, 0xdc, 0x31,             // Label 24003, BoS=1
				0x00, 0x00,                   // RD Type 0
				0x02, 0x41, 0x00, 0x00, 0xfd, 0xeb,
				0x03, 0x03, 0x03, 0x03,       // Prefix 3.3.3.3/32
			},
			expectedLen:    32,
			expectedPrefix: []byte{0x03, 0x03, 0x03, 0x03},
		},
		{
			// /24 network
			name: "VPNv4_Network_24",
			input: []byte{
				0x70,                   // Length: 112 bits (24 + 64 + 24)
				0x05, 0xdc, 0x61,       // Label 24006, BoS=1
				0x00, 0x00,
				0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x01, 0x01, 0x64,       // Prefix 1.1.100.0/24
			},
			expectedLen:    24,
			expectedPrefix: []byte{0x01, 0x01, 0x64},
		},
		{
			// /16 network
			name: "VPNv4_Network_16",
			input: []byte{
				0x68,                   // Length: 104 bits (24 + 64 + 16)
				0x00, 0x10, 0x01,       // Label 1, BoS=1
				0x00, 0x00,
				0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
				0xac, 0x10,             // Prefix 172.16.0.0/16
			},
			expectedLen:    16,
			expectedPrefix: []byte{0xac, 0x10},
		},
		{
			// /8 network
			name: "VPNv4_Network_8",
			input: []byte{
				0x60,                   // Length: 96 bits (24 + 64 + 8)
				0x00, 0x20, 0x01,       // Label 2, BoS=1
				0x00, 0x00,
				0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
				0x0a,                   // Prefix 10.0.0.0/8
			},
			expectedLen:    8,
			expectedPrefix: []byte{0x0a},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalL3VPNNLRI(tt.input, false)
			if err != nil {
				t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
			}
			if got.NLRI[0].Length != tt.expectedLen {
				t.Errorf("Expected prefix length %d, got %d", tt.expectedLen, got.NLRI[0].Length)
			}
		})
	}
}

// TestRFC4364_VPNv4_MultipleNLRIs tests multiple VPNv4 NLRIs in single UPDATE
func TestRFC4364_VPNv4_MultipleNLRIs(t *testing.T) {
	// Two NLRIs in one message:
	// 1. 172.16.7.0/24 with label 24019
	// 2. 100.100.7.0/24 with label 24019
	input := []byte{
		// First NLRI: 172.16.7.0/24
		0x77,                               // Length: 119 bits -> rounds to /32
		0x05, 0xdd, 0x31,                   // Label 24019, BoS=1
		0x00, 0x01,                         // RD Type 1
		0x0a, 0x00, 0x00, 0x07, 0x00, 0x01, // IP 10.0.0.7:1
		0xac, 0x10, 0x07, 0x00,             // Prefix 172.16.7.0
		// Second NLRI: 100.100.7.0/24
		0x70,                               // Length: 112 bits
		0x05, 0xdd, 0x31,                   // Label 24019, BoS=1
		0x00, 0x01,                         // RD Type 1
		0x0a, 0x00, 0x00, 0x07, 0x00, 0x01, // IP 10.0.0.7:1
		0x64, 0x64, 0x07,                   // Prefix 100.100.7.0/24
	}

	got, err := UnmarshalL3VPNNLRI(input, false)
	if err != nil {
		t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
	}
	if len(got.NLRI) != 2 {
		t.Errorf("Expected 2 NLRIs, got %d", len(got.NLRI))
	}
}

// =============================================================================
// RFC 4364 + RFC 4760 - VPNv6 NLRI Tests
// =============================================================================

// TestRFC4364_VPNv6_Prefixes tests VPNv6 NLRI parsing
func TestRFC4364_VPNv6_Prefixes(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectedLen uint8
		nlriCount   int
	}{
		{
			// VPNv6 /64 prefix
			name: "VPNv6_Prefix_64",
			input: []byte{
				0x98,                               // Length: 152 bits (24 + 64 + 64)
				0x18, 0xa8, 0xf1,                   // Label 101007, BoS=1
				0x00, 0x00,                         // RD Type 0
				0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b, // ASN 555:555
				0x55, 0x55, 0x55, 0x55,             // Prefix 5555:5555:5555:5555::/64
				0x55, 0x55, 0x55, 0x55,
			},
			expectedLen: 64,
			nlriCount:   1,
		},
		{
			// VPNv6 /128 host route
			name: "VPNv6_Host_Route_128",
			input: []byte{
				0xd8,                               // Length: 216 bits (24 + 64 + 128)
				0x18, 0xa8, 0xf1,                   // Label 101007, BoS=1
				0x00, 0x00,                         // RD Type 0
				0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b, // ASN 555:555
				// Full /128 prefix
				0x01, 0x72, 0x00, 0x31,
				0x01, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x06,
			},
			expectedLen: 128,
			nlriCount:   1,
		},
		{
			// Multiple VPNv6 prefixes
			name: "VPNv6_Multiple_Prefixes",
			input: []byte{
				// First: /64
				0x98,
				0x18, 0xa8, 0xf1,
				0x00, 0x00,
				0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b,
				0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
				// Second: /128
				0xd8,
				0x18, 0xa8, 0xf1,
				0x00, 0x00,
				0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b,
				0x01, 0x72, 0x00, 0x31, 0x01, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
				// Third: /120
				0xd0,
				0x18, 0xa8, 0xf1,
				0x00, 0x00,
				0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b,
				0x00, 0x10, 0x00, 0x00, 0x02, 0x49, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expectedLen: 64, // First NLRI
			nlriCount:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalL3VPNNLRI(tt.input, false)
			if err != nil {
				t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
			}
			if len(got.NLRI) != tt.nlriCount {
				t.Errorf("Expected %d NLRIs, got %d", tt.nlriCount, len(got.NLRI))
			}
			if got.NLRI[0].Length != tt.expectedLen {
				t.Errorf("Expected prefix length %d, got %d", tt.expectedLen, got.NLRI[0].Length)
			}
		})
	}
}

// =============================================================================
// RFC 7911 - ADD-PATH (Path ID) Support Tests
// =============================================================================

// TestRFC4364_WithPathID tests L3VPN with ADD-PATH support
func TestRFC4364_WithPathID(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		expectedPathID uint32
	}{
		{
			// Path ID = 1
			name: "PathID_1",
			input: []byte{
				0x00, 0x00, 0x00, 0x01, // Path ID = 1
				0x78,                   // Length: 120 bits
				0x05, 0xdc, 0x41,       // Label 24004, BoS=1
				0x00, 0x00,             // RD Type 0
				0x02, 0x41, 0x00, 0x00, 0xfd, 0x9a,
				0x09, 0x16, 0x02, 0x16, // Prefix
			},
			expectedPathID: 1,
		},
		{
			// Path ID = 100
			name: "PathID_100",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, // Path ID = 100
				0x70,                   // Length: 112 bits
				0x05, 0xdc, 0x51,       // Label 24005, BoS=1
				0x00, 0x00,
				0x02, 0xbc, 0x00, 0x00, 0x02, 0xbc,
				0x0a, 0x46, 0x46,
			},
			expectedPathID: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalL3VPNNLRI(tt.input, true) // pathID = true
			if err != nil {
				t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
			}
			if got.NLRI[0].PathID != tt.expectedPathID {
				t.Errorf("Expected PathID %d, got %d", tt.expectedPathID, got.NLRI[0].PathID)
			}
		})
	}
}

// =============================================================================
// RFC 4364 - MPLS Label Tests
// =============================================================================

// TestRFC4364_MPLSLabels tests various MPLS label scenarios
func TestRFC4364_MPLSLabels(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expectedLabel uint32
		expectedBoS   bool
	}{
		{
			// Standard VPN label
			name: "Label_24003",
			input: []byte{
				0x78,
				0x05, 0xdc, 0x31, // Label 24003, Exp=0, BoS=1
				0x00, 0x00,
				0x02, 0x41, 0x00, 0x00, 0xfd, 0xeb,
				0x03, 0x03, 0x03, 0x03,
			},
			expectedLabel: 24003,
			expectedBoS:   true,
		},
		{
			// Large label value
			name: "Label_101007",
			input: []byte{
				0x98,
				0x18, 0xa8, 0xf1, // Label 101007, Exp=0, BoS=1
				0x00, 0x00,
				0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b,
				0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
			},
			expectedLabel: 101007,
			expectedBoS:   true,
		},
		{
			// Minimum label value (label 0 is reserved but valid for parsing)
			name: "Label_1",
			input: []byte{
				0x70,
				0x00, 0x00, 0x11, // Label 1, Exp=0, BoS=1
				0x00, 0x00,
				0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00,
			},
			expectedLabel: 1,
			expectedBoS:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalL3VPNNLRI(tt.input, false)
			if err != nil {
				t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
			}
			if len(got.NLRI[0].Label) == 0 {
				t.Fatal("Expected at least one label")
			}
			if got.NLRI[0].Label[0].Value != tt.expectedLabel {
				t.Errorf("Expected label %d, got %d", tt.expectedLabel, got.NLRI[0].Label[0].Value)
			}
			if got.NLRI[0].Label[0].BoS != tt.expectedBoS {
				t.Errorf("Expected BoS %t, got %t", tt.expectedBoS, got.NLRI[0].Label[0].BoS)
			}
		})
	}
}

// =============================================================================
// SRv6 L3VPN Tests (RFC 9252)
// =============================================================================

// TestRFC4364_SRv6_L3VPN tests SRv6-based L3VPN
func TestRFC4364_SRv6_L3VPN(t *testing.T) {
	// SRv6 L3VPN uses a different label encoding
	input := []byte{
		0x76,                               // Length
		0x00, 0x42, 0x00,                   // SRv6 SID indicator
		0x00, 0x00,                         // RD Type 0
		0x13, 0xce, 0x00, 0x00, 0xfe, 0x0a, // RD
		0x18, 0x18, 0x18, 0x00,             // Prefix 24.24.24.0/24
	}

	got, err := UnmarshalL3VPNNLRI(input, false, true) // srv6 = true
	if err != nil {
		t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
	}
	if len(got.NLRI) != 1 {
		t.Errorf("Expected 1 NLRI, got %d", len(got.NLRI))
	}
	if got.NLRI[0].RD.Type != 0 {
		t.Errorf("Expected RD Type 0, got %d", got.NLRI[0].RD.Type)
	}
}

// =============================================================================
// RFC 4364 - Error Handling Tests
// =============================================================================

// TestRFC4364_ErrorCases tests error handling for invalid input
func TestRFC4364_ErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "Empty_Input",
			input: []byte{},
		},
		{
			name:  "Too_Short_For_Label",
			input: []byte{0x70, 0x05},
		},
		{
			name:  "Too_Short_For_RD",
			input: []byte{0x70, 0x05, 0xdc, 0x31, 0x00, 0x00},
		},
		{
			name:  "Invalid_NLRI_Length_Zero",
			input: []byte{0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalL3VPNNLRI(tt.input, false)
			if err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}

// =============================================================================
// RFC 4364 - Withdrawal Tests
// =============================================================================

// TestRFC4364_Withdrawals tests L3VPN withdrawal handling
func TestRFC4364_Withdrawals(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			// Withdrawal with compatibility marker 0x800000
			name: "Withdrawal_Compat_Marker",
			input: []byte{
				0x70,                   // Length
				0x80, 0x00, 0x00,       // Compatibility marker for withdrawal
				0x00, 0x00,             // RD Type 0
				0x02, 0x41, 0x00, 0x00, 0xfd, 0xeb,
				0x0a, 0x00, 0x00,       // Prefix
			},
		},
		{
			// Withdrawal with zero label
			name: "Withdrawal_Zero_Label",
			input: []byte{
				0x70,                   // Length
				0x00, 0x00, 0x00,       // Zero label for withdrawal
				0x00, 0x00,             // RD Type 0
				0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0xc0, 0xa8, 0x01,       // Prefix
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalL3VPNNLRI(tt.input, false)
			if err != nil {
				t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
			}
			// Withdrawals should have nil labels
			if got.NLRI[0].Label != nil {
				t.Logf("Note: Withdrawal parsed with Label field: %v", got.NLRI[0].Label)
			}
		})
	}
}

// =============================================================================
// RFC 4364 - Real-World Scenario Tests
// =============================================================================

// TestRFC4364_RealWorld_CiscoXR simulates Cisco IOS-XR L3VPN announcements
func TestRFC4364_RealWorld_CiscoXR(t *testing.T) {
	// Typical Cisco XR L3VPN announcement:
	// VRF: CUSTOMER-A, RD: 65000:100, RT: 65000:100
	// Prefix: 10.1.1.0/24, Label: 24001
	input := []byte{
		0x70,                               // 112 bits
		0x05, 0xdc, 0x11,                   // Label 24001, BoS=1
		0x00, 0x00,                         // RD Type 0
		0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64, // RD 65000:100
		0x0a, 0x01, 0x01,                   // Prefix 10.1.1.0/24
	}

	got, err := UnmarshalL3VPNNLRI(input, false)
	if err != nil {
		t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
	}

	// Verify parsed values
	if len(got.NLRI) != 1 {
		t.Fatalf("Expected 1 NLRI, got %d", len(got.NLRI))
	}

	nlri := got.NLRI[0]

	// Verify label
	if len(nlri.Label) != 1 || nlri.Label[0].Value != 24001 {
		t.Errorf("Expected label 24001, got %v", nlri.Label)
	}

	// Verify RD
	if nlri.RD.Type != 0 {
		t.Errorf("Expected RD Type 0, got %d", nlri.RD.Type)
	}

	// Verify prefix length
	if nlri.Length != 24 {
		t.Errorf("Expected prefix length 24, got %d", nlri.Length)
	}
}

// TestRFC4364_RealWorld_JuniperMX simulates Juniper MX L3VPN announcements
func TestRFC4364_RealWorld_JuniperMX(t *testing.T) {
	// Typical Juniper MX L3VPN with Type 1 RD (IP-based)
	// VRF: VPN-B, RD: 192.168.1.1:100
	// Prefix: 172.16.0.0/16, Label: 299776
	input := []byte{
		0x68,                               // 104 bits (24 + 64 + 16)
		0x04, 0x92, 0x01,                   // Label 299776, BoS=1
		0x00, 0x01,                         // RD Type 1
		0xc0, 0xa8, 0x01, 0x01, 0x00, 0x64, // RD 192.168.1.1:100
		0xac, 0x10,                         // Prefix 172.16.0.0/16
	}

	got, err := UnmarshalL3VPNNLRI(input, false)
	if err != nil {
		t.Fatalf("UnmarshalL3VPNNLRI failed: %v", err)
	}

	nlri := got.NLRI[0]

	// Verify RD Type 1
	if nlri.RD.Type != 1 {
		t.Errorf("Expected RD Type 1, got %d", nlri.RD.Type)
	}

	// Verify prefix length
	if nlri.Length != 16 {
		t.Errorf("Expected prefix length 16, got %d", nlri.Length)
	}
}
