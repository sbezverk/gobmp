package evpn

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// TestRFC9251_SMET tests RFC 9251 Section 9.1 - Selective Multicast Ethernet Tag Route
func TestRFC9251_SMET(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		want        *SMET
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid SMET - IPv4, no source, flags 0x0F",
			input: []byte{
				// RD Type 0 (8 bytes): 0:100:200
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				// Ethernet Tag ID (4 bytes): 1000
				0x00, 0x00, 0x03, 0xe8,
				// Multicast Source Length: 0 (no source)
				0x00,
				// Multicast Group Length: 32 bits
				0x20,
				// Multicast Group Address (4 bytes): 239.1.1.1
				0xef, 0x01, 0x01, 0x01,
				// Originator Router Length: 32 bits
				0x20,
				// Originator Router Address (4 bytes): 10.0.0.1
				0x0a, 0x00, 0x00, 0x01,
				// Flags: 0x0F (all IGMP versions)
				0x0f,
			},
			want: &SMET{
				RD:                &base.RD{Type: 0, Value: []byte{0x00, 0x64, 0x00, 0x00, 0x00, 0xc8}},
				EthTag:            []byte{0x00, 0x00, 0x03, 0xe8},
				McastSrcLen:       0,
				McastSrcAddr:      nil,
				McastGrpLen:       32,
				McastGrpAddr:      []byte{0xef, 0x01, 0x01, 0x01},
				OriginatorRtrLen:  32,
				OriginatorRtrAddr: []byte{0x0a, 0x00, 0x00, 0x01},
				Flags:             0x0f,
			},
			wantErr: false,
		},
		{
			name: "Valid SMET - IPv4, IPv4 source, flags 0x04",
			input: []byte{
				// RD Type 1 (8 bytes): 192.0.2.1:100
				0x00, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x64,
				// Ethernet Tag ID (4 bytes): 0
				0x00, 0x00, 0x00, 0x00,
				// Multicast Source Length: 32 bits
				0x20,
				// Multicast Source Address (4 bytes): 10.1.1.1
				0x0a, 0x01, 0x01, 0x01,
				// Multicast Group Length: 32 bits
				0x20,
				// Multicast Group Address (4 bytes): 239.2.2.2
				0xef, 0x02, 0x02, 0x02,
				// Originator Router Length: 32 bits
				0x20,
				// Originator Router Address (4 bytes): 192.168.1.1
				0xc0, 0xa8, 0x01, 0x01,
				// Flags: 0x04 (v3 only)
				0x04,
			},
			want: &SMET{
				RD:                &base.RD{Type: 1, Value: []byte{0xc0, 0x00, 0x02, 0x01, 0x00, 0x64}},
				EthTag:            []byte{0x00, 0x00, 0x00, 0x00},
				McastSrcLen:       32,
				McastSrcAddr:      []byte{0x0a, 0x01, 0x01, 0x01},
				McastGrpLen:       32,
				McastGrpAddr:      []byte{0xef, 0x02, 0x02, 0x02},
				OriginatorRtrLen:  32,
				OriginatorRtrAddr: []byte{0xc0, 0xa8, 0x01, 0x01},
				Flags:             0x04,
			},
			wantErr: false,
		},
		{
			name: "Valid SMET - IPv6, IPv6 source",
			input: []byte{
				// RD Type 2 (8 bytes): 65536:999
				0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x03, 0xe7,
				// Ethernet Tag ID (4 bytes): 100
				0x00, 0x00, 0x00, 0x64,
				// Multicast Source Length: 128 bits
				0x80,
				// Multicast Source Address (16 bytes): 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// Multicast Group Length: 128 bits
				0x80,
				// Multicast Group Address (16 bytes): ff0e::1
				0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// Originator Router Length: 128 bits
				0x80,
				// Originator Router Address (16 bytes): 2001:db8::100
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
				// Flags: 0x0c (v3 and v2)
				0x0c,
			},
			want: &SMET{
				RD:      &base.RD{Type: 2, Value: []byte{0x00, 0x01, 0x00, 0x00, 0x03, 0xe7}},
				EthTag:  []byte{0x00, 0x00, 0x00, 0x64},
				McastSrcLen: 128,
				McastSrcAddr: []byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				McastGrpLen: 128,
				McastGrpAddr: []byte{
					0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				OriginatorRtrLen: 128,
				OriginatorRtrAddr: []byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
				},
				Flags: 0x0c,
			},
			wantErr: false,
		},
		{
			name: "Valid SMET - IPv6 group, IPv4 originator",
			input: []byte{
				// RD Type 0 (8 bytes)
				0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x14,
				// Ethernet Tag ID (4 bytes)
				0xff, 0xff, 0xff, 0xff,
				// Multicast Source Length: 0
				0x00,
				// Multicast Group Length: 128 bits
				0x80,
				// Multicast Group Address (16 bytes)
				0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
				// Originator Router Length: 32 bits
				0x20,
				// Originator Router Address (4 bytes)
				0x0a, 0x00, 0x00, 0xfe,
				// Flags: 0x00
				0x00,
			},
			want: &SMET{
				RD:           &base.RD{Type: 0, Value: []byte{0x00, 0x0a, 0x00, 0x00, 0x00, 0x14}},
				EthTag:       []byte{0xff, 0xff, 0xff, 0xff},
				McastSrcLen:  0,
				McastSrcAddr: nil,
				McastGrpLen:  128,
				McastGrpAddr: []byte{
					0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
				},
				OriginatorRtrLen:  32,
				OriginatorRtrAddr: []byte{0x0a, 0x00, 0x00, 0xfe},
				Flags:             0x00,
			},
			wantErr: false,
		},
		{
			name: "Valid SMET - IPv4 group, IPv6 originator",
			input: []byte{
				// RD Type 1 (8 bytes): 10.0.0.1:500
				0x00, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x01, 0xf4,
				// Ethernet Tag ID (4 bytes): 200
				0x00, 0x00, 0x00, 0xc8,
				// Multicast Source Length: 0
				0x00,
				// Multicast Group Length: 32 bits
				0x20,
				// Multicast Group Address (4 bytes): 239.255.1.1
				0xef, 0xff, 0x01, 0x01,
				// Originator Router Length: 128 bits
				0x80,
				// Originator Router Address (16 bytes): 2001:db8::200
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
				// Flags: 0x02 (v2)
				0x02,
			},
			want: &SMET{
				RD:           &base.RD{Type: 1, Value: []byte{0x0a, 0x00, 0x00, 0x01, 0x01, 0xf4}},
				EthTag:       []byte{0x00, 0x00, 0x00, 0xc8},
				McastSrcLen:  0,
				McastSrcAddr: nil,
				McastGrpLen:  32,
				McastGrpAddr: []byte{0xef, 0xff, 0x01, 0x01},
				OriginatorRtrLen: 128,
				OriginatorRtrAddr: []byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
				},
				Flags: 0x02,
			},
			wantErr: false,
		},
		{
			name: "Invalid - Too short (less than minimum 24 bytes)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x03, 0xe8,
				0x00,
				0x20,
				0xef, 0x01, 0x01, 0x01,
				0x20,
				// Missing originator address and flags
			},
			wantErr:     true,
			errContains: "need at least 24 bytes",
		},
		{
			name: "Invalid - Invalid multicast source length (64)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x03, 0xe8,
				0x40, // Invalid: 64 bits
				0x20,
				0xef, 0x01, 0x01, 0x01,
				0x20,
				0x0a, 0x00, 0x00, 0x01,
				0x0f,
			},
			wantErr:     true,
			errContains: "invalid multicast source address length",
		},
		{
			name: "Invalid - Invalid multicast group length (0)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x03, 0xe8,
				0x00,
				0x00, // Invalid: 0 bits
				0x00, 0x00, 0x00, 0x00, // Pad to 24 bytes: dummy group addr
				0x20,
				0x0a, 0x00, 0x00, 0x01,
				0x0f,
			},
			wantErr:     true,
			errContains: "invalid multicast group address length",
		},
		{
			name: "Invalid - Invalid originator router length (64)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x03, 0xe8,
				0x00,
				0x20,
				0xef, 0x01, 0x01, 0x01,
				0x40, // Invalid: 64 bits
				0x0a, 0x00, 0x00, 0x01,
				0x0f,
			},
			wantErr:     true,
			errContains: "invalid originator router address length",
		},
		{
			name: "Invalid - Truncated multicast source address",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x03, 0xe8,
				0x20,         // Expect 4 bytes
				0x0a, 0x01,   // Only 2 bytes provided
			},
			wantErr:     true,
			errContains: "need at least 24 bytes",
		},
		{
			name: "Invalid - Truncated multicast group address",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x03, 0xe8,
				0x00,
				0x20,
				0xef, 0x01, // Only 2 bytes instead of 4
			},
			wantErr:     true,
			errContains: "need at least 24 bytes",
		},
		{
			name: "Invalid - Truncated originator router address",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x03, 0xe8,
				0x00,
				0x20,
				0xef, 0x01, 0x01, 0x01,
				0x20,
				0x0a, 0x00, // Only 2 bytes instead of 4
			},
			wantErr:     true,
			errContains: "need at least 24 bytes",
		},
		{
			name: "Invalid - Missing flags byte",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x03, 0xe8,
				0x00,
				0x20,
				0xef, 0x01, 0x01, 0x01,
				0x20,
				0x0a, 0x00, 0x00, 0x01,
				// Missing flags byte
			},
			wantErr:     true,
			errContains: "need at least 24 bytes",
		},
		{
			name: "Invalid - Extra bytes after flags",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x03, 0xe8,
				0x00,
				0x20,
				0xef, 0x01, 0x01, 0x01,
				0x20,
				0x0a, 0x00, 0x00, 0x01,
				0x0f,
				0xff, // Extra byte
			},
			wantErr:     true,
			errContains: "invalid length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNSMET(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalEVPNSMET() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errContains != "" && err != nil {
					if !strings.Contains(err.Error(), tt.errContains) {
						t.Errorf("UnmarshalEVPNSMET() error = %v, should contain %v", err, tt.errContains)
					}
				}
				return
			}
			// Use DeepEqual on entire struct to validate ALL fields
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalEVPNSMET() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRFC9251_SMET_InterfaceMethods tests that Type 6 implements RouteTypeSpec correctly
func TestRFC9251_SMET_InterfaceMethods(t *testing.T) {
	rd, err := base.MakeRD([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8})
	if err != nil {
		t.Fatalf("base.MakeRD() error = %v", err)
	}
	smet := &SMET{
		RD:                rd,
		EthTag:            []byte{0x00, 0x00, 0x03, 0xe8},
		McastSrcLen:       0,
		McastSrcAddr:      nil,
		McastGrpLen:       32,
		McastGrpAddr:      []byte{0xef, 0x01, 0x01, 0x01},
		OriginatorRtrLen:  32,
		OriginatorRtrAddr: []byte{0x0a, 0x00, 0x00, 0x01},
		Flags:             0x0f,
	}

	// Test GetRouteTypeSpec
	spec := smet.GetRouteTypeSpec()
	if spec != smet {
		t.Errorf("GetRouteTypeSpec() = %v, want %v", spec, smet)
	}

	// Test getRD
	rdStr := smet.getRD()
	if rdStr == "" {
		t.Error("getRD() returned empty string")
	}

	// Test getTag
	tag := smet.getTag()
	if !reflect.DeepEqual(tag, smet.EthTag) {
		t.Errorf("getTag() = %v, want %v", tag, smet.EthTag)
	}

	// Test methods that should return nil for Type 6
	if smet.getESI() != nil {
		t.Error("getESI() should return nil for Type 6")
	}
	if smet.getMAC() != nil {
		t.Error("getMAC() should return nil for Type 6")
	}
	if smet.getMACLength() != nil {
		t.Error("getMACLength() should return nil for Type 6")
	}
	if smet.getIPAddress() != nil {
		t.Error("getIPAddress() should return nil for Type 6")
	}
	if smet.getIPLength() != nil {
		t.Error("getIPLength() should return nil for Type 6")
	}
	if smet.getGWAddress() != nil {
		t.Error("getGWAddress() should return nil for Type 6")
	}
	if smet.getLabel() != nil {
		t.Error("getLabel() should return nil for Type 6")
	}
}

// TestRFC9251_SMET_UnmarshalEVPNNLRI tests Type 6 integration with full NLRI parsing
func TestRFC9251_SMET_UnmarshalEVPNNLRI(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name: "Valid NLRI with single Type 6 route - IPv4",
			input: []byte{
				0x06, // Route Type 6
				0x18, // Length: 24 bytes
				// RD Type 0
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				// Ethernet Tag ID
				0x00, 0x00, 0x03, 0xe8,
				// Multicast Source Length: 0
				0x00,
				// Multicast Group Length: 32
				0x20,
				// Multicast Group Address
				0xef, 0x01, 0x01, 0x01,
				// Originator Router Length: 32
				0x20,
				// Originator Router Address
				0x0a, 0x00, 0x00, 0x01,
				// Flags
				0x0f,
			},
			wantErr: false,
		},
		{
			name: "Valid NLRI with single Type 6 route - IPv6",
			input: []byte{
				0x06, // Route Type 6
				0x40, // Length: 64 bytes
				// RD Type 0
				0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x14,
				// Ethernet Tag ID
				0x00, 0x00, 0x00, 0x64,
				// Multicast Source Length: 128
				0x80,
				// Multicast Source Address (16 bytes)
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// Multicast Group Length: 128
				0x80,
				// Multicast Group Address (16 bytes)
				0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// Originator Router Length: 128
				0x80,
				// Originator Router Address (16 bytes)
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
				// Flags
				0x04,
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
					if route.RouteType != 6 {
						t.Errorf("Route type = %d, want 6", route.RouteType)
					}
					if _, ok := route.RouteTypeSpec.(*SMET); !ok {
						t.Errorf("RouteTypeSpec type = %T, want *SMET", route.RouteTypeSpec)
					}
				}
			}
		})
	}
}
