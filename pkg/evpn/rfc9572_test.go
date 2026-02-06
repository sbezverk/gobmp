package evpn

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// TestRFC9572_PerRegionIPMSIAD tests RFC 9572 Section 3.1 Per-Region I-PMSI A-D Route
func TestRFC9572_PerRegionIPMSIAD(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		want        *PerRegionIPMSIAD
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid Type 9 - RD Type 0, zero Ethernet Tag, Region ID type 0",
			input: []byte{
				// RD Type 0 (8 bytes): 0:100:200
				0x00, 0x00, // Type 0
				0x00, 0x64, // AS 100
				0x00, 0x00, 0x00, 0xc8, // Value 200
				// Ethernet Tag ID (4 bytes): 0
				0x00, 0x00, 0x00, 0x00,
				// Region ID (8 bytes): Extended Community Type 0
				0x00, 0x02, // Type/Subtype
				0x00, 0x0a, // AS 10
				0x00, 0x00, 0x00, 0x01, // Value 1
			},
			want: &PerRegionIPMSIAD{
				RD:       &base.RD{Type: 0, Value: []byte{0x00, 0x64, 0x00, 0x00, 0x00, 0xc8}},
				EthTag:   []byte{0x00, 0x00, 0x00, 0x00},
				RegionID: []byte{0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01},
			},
			wantErr: false,
		},
		{
			name: "Valid Type 9 - RD Type 1, non-zero Ethernet Tag",
			input: []byte{
				// RD Type 1 (8 bytes): 192.0.2.1:500
				0x00, 0x01, // Type 1
				0xc0, 0x00, 0x02, 0x01, // IP 192.0.2.1
				0x01, 0xf4, // Value 500
				// Ethernet Tag ID (4 bytes): 100
				0x00, 0x00, 0x00, 0x64,
				// Region ID (8 bytes): Type 1
				0x01, 0x02, // Type/Subtype
				0xc0, 0x00, 0x02, 0x0a, // IP 192.0.2.10
				0x00, 0x64, // Value 100
			},
			want: &PerRegionIPMSIAD{
				RD:       &base.RD{Type: 1, Value: []byte{0xc0, 0x00, 0x02, 0x01, 0x01, 0xf4}},
				EthTag:   []byte{0x00, 0x00, 0x00, 0x64},
				RegionID: []byte{0x01, 0x02, 0xc0, 0x00, 0x02, 0x0a, 0x00, 0x64},
			},
			wantErr: false,
		},
		{
			name: "Valid Type 9 - RD Type 2, max Ethernet Tag",
			input: []byte{
				// RD Type 2 (8 bytes): 65536:999
				0x00, 0x02, // Type 2
				0x00, 0x01, 0x00, 0x00, // AS 65536
				0x03, 0xe7, // Value 999
				// Ethernet Tag ID (4 bytes): 0xFFFFFFFF
				0xff, 0xff, 0xff, 0xff,
				// Region ID (8 bytes): Type 2
				0x02, 0x02, // Type/Subtype
				0x00, 0x01, 0x00, 0x01, // AS 65537
				0x00, 0x0a, // Value 10
			},
			want: &PerRegionIPMSIAD{
				RD:       &base.RD{Type: 2, Value: []byte{0x00, 0x01, 0x00, 0x00, 0x03, 0xe7}},
				EthTag:   []byte{0xff, 0xff, 0xff, 0xff},
				RegionID: []byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0a},
			},
			wantErr: false,
		},
		{
			name: "Valid Type 9 - All zeros",
			input: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // RD: all zeros
				0x00, 0x00, 0x00, 0x00, // EthTag: 0
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // RegionID: all zeros
			},
			want: &PerRegionIPMSIAD{
				RD:       &base.RD{Type: 0, Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				EthTag:   []byte{0x00, 0x00, 0x00, 0x00},
				RegionID: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			},
			wantErr: false,
		},
		{
			name: "Invalid - Truncated after RD",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD only
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Truncated after Ethernet Tag",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, // EthTag
				// Missing RegionID
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Truncated in Region ID",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00, 0x02, 0x00, 0x0a, // Partial RegionID (4 bytes)
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name:        "Invalid - Empty input",
			input:       []byte{},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Too long (21 bytes)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01,
				0xff, // Extra byte
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Too short (19 bytes)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x01,
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Valid Type 9 - Real-world scenario: Multi-region EVPN",
			input: []byte{
				// RD Type 0: 64512:100 (Private AS range)
				0x00, 0x00,
				0xfc, 0x00, // AS 64512
				0x00, 0x00, 0x00, 0x64, // Value 100
				// Ethernet Tag ID: 1000 (VLAN-aware bundle)
				0x00, 0x00, 0x03, 0xe8,
				// Region ID: 0:1:1 (Region 1 in datacenter)
				0x00, 0x02,
				0x00, 0x01, // AS 1
				0x00, 0x00, 0x00, 0x01, // Region 1
			},
			want: &PerRegionIPMSIAD{
				RD:       &base.RD{Type: 0, Value: []byte{0xfc, 0x00, 0x00, 0x00, 0x00, 0x64}},
				EthTag:   []byte{0x00, 0x00, 0x03, 0xe8},
				RegionID: []byte{0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01},
			},
			wantErr: false,
		},
		{
			name: "Valid Type 9 - Different Region ID Extended Community type",
			input: []byte{
				// RD Type 1: 10.0.0.1:200
				0x00, 0x01,
				0x0a, 0x00, 0x00, 0x01, // IP 10.0.0.1
				0x00, 0xc8, // Value 200
				// Ethernet Tag ID: 500
				0x00, 0x00, 0x01, 0xf4,
				// Region ID: Different Extended Community format
				0x80, 0x0e, // Opaque Extended Community
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			},
			want: &PerRegionIPMSIAD{
				RD:       &base.RD{Type: 1, Value: []byte{0x0a, 0x00, 0x00, 0x01, 0x00, 0xc8}},
				EthTag:   []byte{0x00, 0x00, 0x01, 0xf4},
				RegionID: []byte{0x80, 0x0e, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNPerRegionIPMSIAD(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalEVPNPerRegionIPMSIAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errContains != "" && err != nil {
					if !contains(err.Error(), tt.errContains) {
						t.Errorf("UnmarshalEVPNPerRegionIPMSIAD() error = %v, should contain %v", err, tt.errContains)
					}
				}
				return
			}
			if !reflect.DeepEqual(got.EthTag, tt.want.EthTag) {
				t.Errorf("UnmarshalEVPNPerRegionIPMSIAD() EthTag = %v, want %v", got.EthTag, tt.want.EthTag)
			}
			if !reflect.DeepEqual(got.RegionID, tt.want.RegionID) {
				t.Errorf("UnmarshalEVPNPerRegionIPMSIAD() RegionID = %v, want %v", got.RegionID, tt.want.RegionID)
			}
			if got.RD.Type != tt.want.RD.Type {
				t.Errorf("UnmarshalEVPNPerRegionIPMSIAD() RD.Type = %v, want %v", got.RD.Type, tt.want.RD.Type)
			}
		})
	}
}

// TestRFC9572_InterfaceMethods tests that Type 9 implements RouteTypeSpec correctly
func TestRFC9572_InterfaceMethods(t *testing.T) {
	rd, _ := base.MakeRD([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8})
	route := &PerRegionIPMSIAD{
		RD:       rd,
		EthTag:   []byte{0x00, 0x00, 0x00, 0x64},
		RegionID: []byte{0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01},
	}

	// Test GetRouteTypeSpec
	spec := route.GetRouteTypeSpec()
	if spec != route {
		t.Errorf("GetRouteTypeSpec() = %v, want %v", spec, route)
	}

	// Test getRD
	rdStr := route.getRD()
	if rdStr == "" {
		t.Error("getRD() returned empty string")
	}

	// Test getTag
	tag := route.getTag()
	if !reflect.DeepEqual(tag, route.EthTag) {
		t.Errorf("getTag() = %v, want %v", tag, route.EthTag)
	}

	// Test methods that should return nil
	if route.getESI() != nil {
		t.Error("getESI() should return nil for Type 9")
	}
	if route.getMAC() != nil {
		t.Error("getMAC() should return nil for Type 9")
	}
	if route.getMACLength() != nil {
		t.Error("getMACLength() should return nil for Type 9")
	}
	if route.getIPAddress() != nil {
		t.Error("getIPAddress() should return nil for Type 9")
	}
	if route.getIPLength() != nil {
		t.Error("getIPLength() should return nil for Type 9")
	}
	if route.getGWAddress() != nil {
		t.Error("getGWAddress() should return nil for Type 9")
	}
	if route.getLabel() != nil {
		t.Error("getLabel() should return nil for Type 9")
	}
}

// TestRFC9572_UnmarshalEVPNNLRI tests Type 9 integration with full NLRI parsing
func TestRFC9572_UnmarshalEVPNNLRI(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name: "Valid NLRI with single Type 9 route",
			input: []byte{
				0x09, // Route Type 9
				0x14, // Length: 20 bytes
				// RD Type 0: 0:100:200
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				// Ethernet Tag ID: 100
				0x00, 0x00, 0x00, 0x64,
				// Region ID
				0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01,
			},
			wantErr: false,
		},
		{
			name: "Valid NLRI with multiple Type 9 routes",
			input: []byte{
				// First Type 9
				0x09, 0x14,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x00, 0x64,
				0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01,
				// Second Type 9
				0x09, 0x14,
				0x00, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x01, 0xf4,
				0x00, 0x00, 0x00, 0xc8,
				0x01, 0x02, 0xc0, 0x00, 0x02, 0x0a, 0x00, 0x64,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNNLRI(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalEVPNNLRI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil || len(got.Route) == 0 {
					t.Error("UnmarshalEVPNNLRI() returned nil or empty route")
				}
				for _, route := range got.Route {
					if route.RouteType != 9 {
						t.Errorf("Route type = %d, want 9", route.RouteType)
					}
					if route.Length != 20 {
						t.Errorf("Route length = %d, want 20", route.Length)
					}
					if _, ok := route.RouteTypeSpec.(*PerRegionIPMSIAD); !ok {
						t.Errorf("RouteTypeSpec type = %T, want *PerRegionIPMSIAD", route.RouteTypeSpec)
					}
				}
			}
		})
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestRFC9572_RDTypes tests all three RD types with Type 9
func TestRFC9572_RDTypes(t *testing.T) {
	tests := []struct {
		name   string
		rdType uint16
		rdVal  []byte
	}{
		{
			name:   "RD Type 0 (2-byte AS)",
			rdType: 0,
			rdVal:  []byte{0x00, 0x64, 0x00, 0x00, 0x00, 0xc8}, // AS 100, Value 200
		},
		{
			name:   "RD Type 1 (IPv4)",
			rdType: 1,
			rdVal:  []byte{0xc0, 0x00, 0x02, 0x01, 0x01, 0xf4}, // 192.0.2.1:500
		},
		{
			name:   "RD Type 2 (4-byte AS)",
			rdType: 2,
			rdVal:  []byte{0x00, 0x01, 0x00, 0x00, 0x03, 0xe7}, // AS 65536, Value 999
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]byte, 20)
			binary.BigEndian.PutUint16(input[0:2], tt.rdType)
			copy(input[2:8], tt.rdVal)
			// Ethernet Tag ID: 0
			// Region ID: zeros
			copy(input[8:12], []byte{0x00, 0x00, 0x00, 0x00})
			copy(input[12:20], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

			got, err := UnmarshalEVPNPerRegionIPMSIAD(input)
			if err != nil {
				t.Fatalf("UnmarshalEVPNPerRegionIPMSIAD() error = %v", err)
			}
			if got.RD.Type != tt.rdType {
				t.Errorf("RD.Type = %d, want %d", got.RD.Type, tt.rdType)
			}
		})
	}
}
