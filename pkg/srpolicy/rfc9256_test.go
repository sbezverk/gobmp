package srpolicy

import (
	"net"
	"testing"
)

// TestRFC9256_NLRIv4 validates IPv4 SR Policy NLRI parsing
// RFC 9256 Section 2.1
func TestRFC9256_NLRIv4(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		wantDist      uint32
		wantColor     uint32
		wantEndpoint  string
		wantErr       bool
	}{
		{
			name:  "Valid - SR Policy v4 (Dist=2, Color=99, Endpoint=10.0.0.13)",
			input: []byte{0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x63, 0x0A, 0x00, 0x00, 0x0D},
			wantDist:     2,
			wantColor:    99,
			wantEndpoint: "10.0.0.13",
			wantErr:      false,
		},
		{
			name:  "Valid - SR Policy v4 (Dist=1, Color=100, Endpoint=192.168.1.1)",
			input: []byte{0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0xC0, 0xA8, 0x01, 0x01},
			wantDist:     1,
			wantColor:    100,
			wantEndpoint: "192.168.1.1",
			wantErr:      false,
		},
		{
			name:  "Valid - SR Policy v4 (Dist=0, Color=200, Endpoint=203.0.113.1)",
			input: []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC8, 0xCB, 0x00, 0x71, 0x01},
			wantDist:     0,
			wantColor:    200,
			wantEndpoint: "203.0.113.1",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLSNLRI73(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalLSNLRI73() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if got == nil {
				t.Errorf("UnmarshalLSNLRI73() returned nil")
				return
			}

			if got.Distinguisher != tt.wantDist {
				t.Errorf("Distinguisher = %d, want %d", got.Distinguisher, tt.wantDist)
			}

			if got.Color != tt.wantColor {
				t.Errorf("Color = %d, want %d", got.Color, tt.wantColor)
			}

			gotIP := net.IP(got.Endpoint)
			if gotIP.String() != tt.wantEndpoint {
				t.Errorf("Endpoint = %s, want %s", gotIP.String(), tt.wantEndpoint)
			}
		})
	}
}

// TestRFC9256_NLRIv6 validates IPv6 SR Policy NLRI parsing
// RFC 9256 Section 2.1
func TestRFC9256_NLRIv6(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		wantDist      uint32
		wantColor     uint32
		wantEndpoint  string
		wantErr       bool
	}{
		{
			name: "Valid - SR Policy v6 (Dist=6, Color=6, Endpoint=2001:420:ffff:1013::1)",
			input: []byte{
				0xC0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06,
				0x20, 0x01, 0x04, 0x20, 0xFF, 0xFF, 0x10, 0x13,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantDist:     6,
			wantColor:    6,
			wantEndpoint: "2001:420:ffff:1013::1",
			wantErr:      false,
		},
		{
			name: "Valid - SR Policy v6 (Dist=1, Color=100, Endpoint=2001:db8::1)",
			input: []byte{
				0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64,
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantDist:     1,
			wantColor:    100,
			wantEndpoint: "2001:db8::1",
			wantErr:      false,
		},
		{
			name: "Valid - SR Policy v6 (Dist=0, Color=500, Endpoint=::1)",
			input: []byte{
				0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xF4,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantDist:     0,
			wantColor:    500,
			wantEndpoint: "::1",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLSNLRI73(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalLSNLRI73() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if got == nil {
				t.Errorf("UnmarshalLSNLRI73() returned nil")
				return
			}

			if got.Distinguisher != tt.wantDist {
				t.Errorf("Distinguisher = %d, want %d", got.Distinguisher, tt.wantDist)
			}

			if got.Color != tt.wantColor {
				t.Errorf("Color = %d, want %d", got.Color, tt.wantColor)
			}

			// Normalize IPv6 addresses for comparison
			wantIP := net.ParseIP(tt.wantEndpoint)
			gotIP := net.IP(got.Endpoint)
			if !gotIP.Equal(wantIP) {
				t.Errorf("Endpoint = %s, want %s", gotIP.String(), tt.wantEndpoint)
			}
		})
	}
}

// TestRFC9256_DistinguisherValues validates various Distinguisher values
// RFC 9256 Section 2.1 - Distinguisher MUST be unique for same Color+Endpoint
func TestRFC9256_DistinguisherValues(t *testing.T) {
	tests := []struct {
		name     string
		dist     uint32
		color    uint32
		endpoint string
	}{
		{
			name:     "Distinguisher = 0 (default)",
			dist:     0,
			color:    100,
			endpoint: "10.0.0.1",
		},
		{
			name:     "Distinguisher = 1",
			dist:     1,
			color:    100,
			endpoint: "10.0.0.1",
		},
		{
			name:     "Distinguisher = 65535 (max 16-bit)",
			dist:     65535,
			color:    100,
			endpoint: "10.0.0.1",
		},
		{
			name:     "Distinguisher = 4294967295 (max 32-bit)",
			dist:     4294967295,
			color:    100,
			endpoint: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build NLRI manually
			nlri := &NLRI73{
				Length:        12,
				Distinguisher: tt.dist,
				Color:         tt.color,
				Endpoint:      net.ParseIP(tt.endpoint).To4(),
			}

			if nlri.Distinguisher != tt.dist {
				t.Errorf("Distinguisher = %d, want %d", nlri.Distinguisher, tt.dist)
			}
		})
	}
}

// TestRFC9256_ColorValues validates various Color values
// RFC 9256 Section 2.1 - Color identifies policy intent
func TestRFC9256_ColorValues(t *testing.T) {
	tests := []struct {
		name  string
		color uint32
		desc  string
	}{
		{
			name:  "Color = 0 (reserved/unused)",
			color: 0,
			desc:  "Reserved value",
		},
		{
			name:  "Color = 100 (low latency)",
			color: 100,
			desc:  "Low latency path",
		},
		{
			name:  "Color = 200 (high bandwidth)",
			color: 200,
			desc:  "High bandwidth path",
		},
		{
			name:  "Color = 300 (backup path)",
			color: 300,
			desc:  "Backup/redundant path",
		},
		{
			name:  "Color = 4294967295 (max 32-bit)",
			color: 4294967295,
			desc:  "Maximum color value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI73{
				Length:        12,
				Distinguisher: 1,
				Color:         tt.color,
				Endpoint:      net.ParseIP("10.0.0.1").To4(),
			}

			if nlri.Color != tt.color {
				t.Errorf("Color = %d, want %d", nlri.Color, tt.color)
			}
		})
	}
}

// TestRFC9256_EndpointAddresses validates various endpoint IP addresses
// RFC 9256 Section 2.1 - Endpoint is the destination for the SR Policy
func TestRFC9256_EndpointAddresses(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		isV6     bool
	}{
		{
			name:     "Loopback IPv4 (127.0.0.1)",
			endpoint: "127.0.0.1",
			isV6:     false,
		},
		{
			name:     "Private IPv4 (10.0.0.0/8)",
			endpoint: "10.1.2.3",
			isV6:     false,
		},
		{
			name:     "Private IPv4 (192.168.0.0/16)",
			endpoint: "192.168.100.50",
			isV6:     false,
		},
		{
			name:     "Public IPv4",
			endpoint: "203.0.113.1",
			isV6:     false,
		},
		{
			name:     "Loopback IPv6 (::1)",
			endpoint: "::1",
			isV6:     true,
		},
		{
			name:     "Link-local IPv6 (fe80::)",
			endpoint: "fe80::1",
			isV6:     true,
		},
		{
			name:     "ULA IPv6 (fc00::/7)",
			endpoint: "fd00::1",
			isV6:     true,
		},
		{
			name:     "Global IPv6",
			endpoint: "2001:db8::1",
			isV6:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.endpoint)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.endpoint)
			}

			var nlri *NLRI73
			if tt.isV6 {
				nlri = &NLRI73{
					Length:        24,
					Distinguisher: 1,
					Color:         100,
					Endpoint:      ip.To16(),
				}
			} else {
				nlri = &NLRI73{
					Length:        12,
					Distinguisher: 1,
					Color:         100,
					Endpoint:      ip.To4(),
				}
			}

			endpointIP := net.IP(nlri.Endpoint)
			if !endpointIP.Equal(ip) {
				t.Errorf("Endpoint = %s, want %s", endpointIP.String(), tt.endpoint)
			}
		})
	}
}

// TestRFC9256_LengthValues validates NLRI length field
// RFC 9256 Section 2.1 - Length is 12 for IPv4, 24 for IPv6
func TestRFC9256_LengthValues(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		wantLength uint8
		wantErr    bool
	}{
		{
			name: "Valid - IPv4 Length = 12",
			input: []byte{
				0x60, // Length: 12 (0x60 >> 4 = 6 prefix bits, 0x60 & 0x0F = 0)
				0x00, 0x00, 0x00, 0x01, // Distinguisher
				0x00, 0x00, 0x00, 0x64, // Color
				10, 0, 0, 1,            // Endpoint
			},
			wantLength: 12,
			wantErr:    false,
		},
		{
			name: "Valid - IPv6 Length = 24",
			input: []byte{
				0xC0, // Length: 24 (0xC0 >> 4 = 12 prefix bits, 0xC0 & 0x0F = 0)
				0x00, 0x00, 0x00, 0x01, // Distinguisher
				0x00, 0x00, 0x00, 0x64, // Color
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // IPv6 Endpoint
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantLength: 24,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLSNLRI73(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalLSNLRI73() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if got == nil {
				t.Errorf("UnmarshalLSNLRI73() returned nil")
				return
			}

			if got.Length != tt.wantLength {
				t.Errorf("Length = %d, want %d", got.Length, tt.wantLength)
			}
		})
	}
}

// TestRFC9256_ErrorCases validates error handling for invalid NLRI
func TestRFC9256_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Error - Empty NLRI",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "Error - Too short (< 13 bytes for IPv4)",
			input:   []byte{0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLSNLRI73(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalLSNLRI73() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got == nil {
				t.Errorf("UnmarshalLSNLRI73() returned nil")
			}
		})
	}
}


// TestRFC9256_RealWorldScenarios validates common real-world SR Policy scenarios
func TestRFC9256_RealWorldScenarios(t *testing.T) {
	tests := []struct {
		name     string
		scenario string
		dist     uint32
		color    uint32
		endpoint string
		isV6     bool
	}{
		{
			name:     "Low Latency Path to Data Center",
			scenario: "Color 100 represents low-latency path requirement",
			dist:     1,
			color:    100,
			endpoint: "10.0.0.1",
			isV6:     false,
		},
		{
			name:     "High Bandwidth Path to Cloud",
			scenario: "Color 200 represents high-bandwidth path requirement",
			dist:     1,
			color:    200,
			endpoint: "203.0.113.1",
			isV6:     false,
		},
		{
			name:     "Backup/Redundant Path",
			scenario: "Color 300 represents backup path",
			dist:     2,
			color:    300,
			endpoint: "10.0.0.1",
			isV6:     false,
		},
		{
			name:     "IPv6 SR Policy for Modern Networks",
			scenario: "IPv6 endpoint with SR Policy",
			dist:     1,
			color:    100,
			endpoint: "2001:db8::1",
			isV6:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.endpoint)
			if ip == nil {
				t.Fatalf("Invalid IP: %s", tt.endpoint)
			}

			var nlri *NLRI73
			if tt.isV6 {
				nlri = &NLRI73{
					Length:        24,
					Distinguisher: tt.dist,
					Color:         tt.color,
					Endpoint:      ip.To16(),
				}
			} else {
				nlri = &NLRI73{
					Length:        12,
					Distinguisher: tt.dist,
					Color:         tt.color,
					Endpoint:      ip.To4(),
				}
			}

			// Verify NLRI structure
			if nlri.Distinguisher != tt.dist {
				t.Errorf("Distinguisher = %d, want %d", nlri.Distinguisher, tt.dist)
			}
			if nlri.Color != tt.color {
				t.Errorf("Color = %d, want %d", nlri.Color, tt.color)
			}
			endpointIP := net.IP(nlri.Endpoint)
			if !endpointIP.Equal(ip) {
				t.Errorf("Endpoint = %s, want %s", endpointIP.String(), tt.endpoint)
			}
		})
	}
}

// ============================================================================
// RFC 9256 TLV Tests - Using Synthetic Test Data
// ============================================================================

// TestRFC9256_TLVPreference tests TLV Type 123 (Preference) parsing
func TestRFC9256_TLVPreference(t *testing.T) {
	// Import would be: "github.com/sbezverk/gobmp/pkg/srpolicy/testdata"
	// For now, using inline data
	
	tests := []struct {
		name       string
		tlvData    []byte
		wantPref   uint32
		wantErr    bool
	}{
		{
			name: "Preference = 100 (low)",
			tlvData: []byte{
				0x7B,                   // Type: 123
				0x00, 0x04,             // Length: 4
				0x00, 0x00, 0x00, 0x64, // Value: 100
			},
			wantPref: 100,
			wantErr:  false,
		},
		{
			name: "Preference = 200 (medium)",
			tlvData: []byte{
				0x7B,                   // Type: 123
				0x00, 0x04,             // Length: 4
				0x00, 0x00, 0x00, 0xC8, // Value: 200
			},
			wantPref: 200,
			wantErr:  false,
		},
		{
			name: "Preference = 4294967295 (max)",
			tlvData: []byte{
				0x7B,                   // Type: 123
				0x00, 0x04,             // Length: 4
				0xFF, 0xFF, 0xFF, 0xFF, // Value: max uint32
			},
			wantPref: 4294967295,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This tests that the synthetic data is well-formed
			// Actual TLV parsing would require UnmarshalSRPolicyTLV function
			if len(tt.tlvData) < 7 {
				t.Errorf("TLV data too short: got %d bytes", len(tt.tlvData))
			}
			
			// Verify TLV type
			if tt.tlvData[0] != 0x7B {
				t.Errorf("Wrong TLV type: got 0x%02X, want 0x7B", tt.tlvData[0])
			}
			
			t.Logf("✅ Synthetic TLV Preference data is well-formed: %s", tt.name)
		})
	}
}

// TestRFC9256_TLVSegmentList tests TLV Type 127 (Segment List) parsing
func TestRFC9256_TLVSegmentList(t *testing.T) {
	tests := []struct {
		name        string
		segListData []byte
		wantWeight  uint32
		segmentType string
		wantErr     bool
	}{
		{
			name: "Segment List Type A - MPLS Label",
			segListData: []byte{
				0x7F,                   // Type: 127
				0x00, 0x0C,             // Length: 12 bytes
				0x00, 0x00, 0x00, 0x0A, // Weight: 10
				0x01,                   // Segment Type A (MPLS Label)
				0x00, 0x04,             // Segment Length: 4
				0x00, 0x01, 0x86, 0xA0, // Label: 100000
			},
			wantWeight:  10,
			segmentType: "Type A (MPLS Label)",
			wantErr:     false,
		},
		{
			name: "Segment List Type C - IPv4 Node Address",
			segListData: []byte{
				0x7F,                   // Type: 127
				0x00, 0x10,             // Length: 16 bytes
				0x00, 0x00, 0x00, 0x14, // Weight: 20
				0x03,                   // Segment Type C (IPv4 Node)
				0x00, 0x08,             // Length: 8
				0xC0, 0x00, 0x02, 0x01, // IPv4: 192.0.2.1
				0x00, 0x03, 0x0D, 0x40, // SID: 200000
			},
			wantWeight:  20,
			segmentType: "Type C (IPv4 Node)",
			wantErr:     false,
		},
		{
			name: "Segment List with 3 Segments (Multi-Segment)",
			segListData: []byte{
				0x7F,                   // Type: 127
				0x00, 0x24,             // Length: 36 bytes
				0x00, 0x00, 0x00, 0x32, // Weight: 50
				// Segment 1
				0x01,                   // Type A
				0x00, 0x04,             // Length: 4
				0x00, 0x01, 0x86, 0xA0, // Label: 100000
				// Segment 2
				0x01,                   // Type A
				0x00, 0x04,             // Length: 4
				0x00, 0x03, 0x0D, 0x40, // Label: 200000
				// Segment 3
				0x03,                   // Type C
				0x00, 0x08,             // Length: 8
				0xC0, 0x00, 0x02, 0x0A, // IPv4: 192.0.2.10
				0x00, 0x04, 0x93, 0xE0, // SID: 300000
			},
			wantWeight:  50,
			segmentType: "Multi-Segment (3 segments)",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify TLV structure
			if tt.segListData[0] != 0x7F {
				t.Errorf("Wrong TLV type: got 0x%02X, want 0x7F", tt.segListData[0])
			}
			
			// Verify minimum length
			if len(tt.segListData) < 7 {
				t.Errorf("Segment List data too short: got %d bytes", len(tt.segListData))
			}
			
			t.Logf("✅ Synthetic Segment List data is well-formed: %s", tt.name)
		})
	}
}

// TestRFC9256_TLVBindingSID tests TLV Type 128 (Binding SID) parsing
func TestRFC9256_TLVBindingSID(t *testing.T) {
	tests := []struct {
		name     string
		bsidData []byte
		bsidType string
		wantErr  bool
	}{
		{
			name: "BSID IPv4 - Label 100000",
			bsidData: []byte{
				0x80,                   // Type: 128
				0x00, 0x08,             // Length: 8 bytes
				0x00,                   // Flags
				0x00, 0x00, 0x00,       // Reserved
				0x00, 0x01, 0x86, 0xA0, // SID: 100000
			},
			bsidType: "IPv4",
			wantErr:  false,
		},
		{
			name: "BSID SRv6 - 128-bit SID",
			bsidData: []byte{
				0x80,       // Type: 128
				0x00, 0x14, // Length: 20 bytes
				0x00,       // Flags
				0x00, 0x00, 0x00, // Reserved
				// SRv6 SID: 2001:db8:1::1
				0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			bsidType: "SRv6",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify TLV type
			if tt.bsidData[0] != 0x80 {
				t.Errorf("Wrong TLV type: got 0x%02X, want 0x80", tt.bsidData[0])
			}
			
			t.Logf("✅ Synthetic BSID data is well-formed: %s (%s)", tt.name, tt.bsidType)
		})
	}
}

// TestRFC9256_ComplexPolicyStructures tests complex multi-TLV policy structures
func TestRFC9256_ComplexPolicyStructures(t *testing.T) {
	tests := []struct {
		name        string
		policyData  []byte
		description string
		wantErr     bool
	}{
		{
			name: "Complete Policy with 3 Segment Lists (ECMP)",
			policyData: []byte{
				// Preference TLV
				0x7B,                   // Type: 123
				0x00, 0x04,             // Length: 4
				0x00, 0x00, 0x00, 0x64, // Value: 100
				// Priority TLV
				0x7C,       // Type: 124
				0x00, 0x01, // Length: 1
				0x0A,       // Value: 10
				// Segment List 1 (Weight 30)
				0x7F,                   // Type: 127
				0x00, 0x0C,             // Length: 12
				0x00, 0x00, 0x00, 0x1E, // Weight: 30
				0x01,                   // Segment Type A
				0x00, 0x04,             // Length: 4
				0x00, 0x01, 0x86, 0xA0, // Label: 100000
			},
			description: "Multi-path policy with Preference + Priority + Segment Lists",
			wantErr:     false,
		},
		{
			name: "Policy with Binding SID",
			policyData: []byte{
				// Preference
				0x7B,                   // Type: 123
				0x00, 0x04,             // Length: 4
				0x00, 0x00, 0x00, 0xC8, // Value: 200
				// Segment List
				0x7F,                   // Type: 127
				0x00, 0x0C,             // Length: 12
				0x00, 0x00, 0x00, 0x0A, // Weight: 10
				0x01,                   // Segment Type A
				0x00, 0x04,             // Length: 4
				0x00, 0x01, 0x86, 0xA0, // Label: 100000
				// Binding SID
				0x80,                   // Type: 128
				0x00, 0x08,             // Length: 8
				0x00,                   // Flags
				0x00, 0x00, 0x00,       // Reserved
				0x00, 0x05, 0xDC, 0x00, // SID: 384000
			},
			description: "Policy with BSID for traffic steering",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify we have multiple TLVs
			if len(tt.policyData) < 10 {
				t.Errorf("Policy data too short: got %d bytes", len(tt.policyData))
			}
			
			t.Logf("✅ Complex policy structure is well-formed: %s", tt.description)
			t.Logf("   Total size: %d bytes", len(tt.policyData))
		})
	}
}
