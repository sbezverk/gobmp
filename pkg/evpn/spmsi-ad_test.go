package evpn

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// TestUnmarshalEVPNSPMSI tests RFC 9572 Section 3.2 S-PMSI A-D Route parsing
func TestUnmarshalEVPNSPMSI(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		want        *SPMSI
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid Type 10 - IPv4 Source and Group, IPv4 Originator",
			input: []byte{
				// RD Type 0 (8 bytes): 0:100:200
				0x00, 0x00, // Type 0
				0x00, 0x64, // AS 100
				0x00, 0x00, 0x00, 0xc8, // Value 200
				// Ethernet Tag ID (4 bytes): 0
				0x00, 0x00, 0x00, 0x00,
				// Multicast Source Length (1 byte): 32 bits
				0x20,
				// Multicast Source Address (4 bytes): 192.0.2.1
				0xc0, 0x00, 0x02, 0x01,
				// Multicast Group Length (1 byte): 32 bits
				0x20,
				// Multicast Group Address (4 bytes): 239.1.1.1
				0xef, 0x01, 0x01, 0x01,
				// Originator Address Length (1 byte): 32 bits
				0x20,
				// Originator Address (4 bytes): 10.0.0.1
				0x0a, 0x00, 0x00, 0x01,
			},
			want: &SPMSI{
				RD:             &base.RD{Type: 0, Value: []byte{0x00, 0x64, 0x00, 0x00, 0x00, 0xc8}},
				EthTag:         []byte{0x00, 0x00, 0x00, 0x00},
				McastSrcLen:    32,
				McastSrcAddr:   []byte{0xc0, 0x00, 0x02, 0x01},
				McastGrpLen:    32,
				McastGrpAddr:   []byte{0xef, 0x01, 0x01, 0x01},
				OriginatorLen:  32,
				OriginatorAddr: []byte{0x0a, 0x00, 0x00, 0x01},
			},
			wantErr: false,
		},
		{
			name: "Valid Type 10 - IPv6 Source and Group, IPv6 Originator",
			input: []byte{
				// RD Type 1 (8 bytes): 192.0.2.1:500
				0x00, 0x01, // Type 1
				0xc0, 0x00, 0x02, 0x01, // IP 192.0.2.1
				0x01, 0xf4, // Value 500
				// Ethernet Tag ID (4 bytes): 100
				0x00, 0x00, 0x00, 0x64,
				// Multicast Source Length (1 byte): 128 bits
				0x80,
				// Multicast Source Address (16 bytes): 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// Multicast Group Length (1 byte): 128 bits
				0x80,
				// Multicast Group Address (16 bytes): ff3e::1
				0xff, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// Originator Address Length (1 byte): 128 bits
				0x80,
				// Originator Address (16 bytes): 2001:db8::100
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
			},
			want: &SPMSI{
				RD:      &base.RD{Type: 1, Value: []byte{0xc0, 0x00, 0x02, 0x01, 0x01, 0xf4}},
				EthTag:  []byte{0x00, 0x00, 0x00, 0x64},
				McastSrcLen: 128,
				McastSrcAddr: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				McastGrpLen: 128,
				McastGrpAddr: []byte{0xff, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				OriginatorLen: 128,
				OriginatorAddr: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
			},
			wantErr: false,
		},
		{
			name: "Valid Type 10 - (*,G) Any-Source Multicast (zero source length)",
			input: []byte{
				// RD Type 2 (8 bytes): 65536:999
				0x00, 0x02, // Type 2
				0x00, 0x01, 0x00, 0x00, // AS 65536
				0x03, 0xe7, // Value 999
				// Ethernet Tag ID (4 bytes): 42
				0x00, 0x00, 0x00, 0x2a,
				// Multicast Source Length (1 byte): 0 bits (wildcard)
				0x00,
				// No Multicast Source Address
				// Multicast Group Length (1 byte): 32 bits
				0x20,
				// Multicast Group Address (4 bytes): 239.100.1.1
				0xef, 0x64, 0x01, 0x01,
				// Originator Address Length (1 byte): 32 bits
				0x20,
				// Originator Address (4 bytes): 172.16.0.1
				0xac, 0x10, 0x00, 0x01,
			},
			want: &SPMSI{
				RD:             &base.RD{Type: 2, Value: []byte{0x00, 0x01, 0x00, 0x00, 0x03, 0xe7}},
				EthTag:         []byte{0x00, 0x00, 0x00, 0x2a},
				McastSrcLen:    0,
				McastSrcAddr:   nil,
				McastGrpLen:    32,
				McastGrpAddr:   []byte{0xef, 0x64, 0x01, 0x01},
				OriginatorLen:  32,
				OriginatorAddr: []byte{0xac, 0x10, 0x00, 0x01},
			},
			wantErr: false,
		},
		{
			name: "Valid Type 10 - Mixed IPv4 source, IPv6 group and originator",
			input: []byte{
				// RD Type 0 (8 bytes): 0:200:300
				0x00, 0x00, // Type 0
				0x00, 0xc8, // AS 200
				0x00, 0x00, 0x01, 0x2c, // Value 300
				// Ethernet Tag ID (4 bytes): 999
				0x00, 0x00, 0x03, 0xe7,
				// Multicast Source Length (1 byte): 32 bits
				0x20,
				// Multicast Source Address (4 bytes): 10.1.1.1
				0x0a, 0x01, 0x01, 0x01,
				// Multicast Group Length (1 byte): 128 bits
				0x80,
				// Multicast Group Address (16 bytes): ff3e::5
				0xff, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				// Originator Address Length (1 byte): 128 bits
				0x80,
				// Originator Address (16 bytes): 2001:db8::200
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
			},
			want: &SPMSI{
				RD:           &base.RD{Type: 0, Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x01, 0x2c}},
				EthTag:       []byte{0x00, 0x00, 0x03, 0xe7},
				McastSrcLen:  32,
				McastSrcAddr: []byte{0x0a, 0x01, 0x01, 0x01},
				McastGrpLen:  128,
				McastGrpAddr: []byte{0xff, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				OriginatorLen: 128,
				OriginatorAddr: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00},
			},
			wantErr: false,
		},
		{
			name: "Valid Type 10 - All zeros (edge case)",
			input: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // RD: all zeros
				0x00, 0x00, 0x00, 0x00, // EthTag: 0
				0x00,                   // McastSrcLen: 0
				0x20,                   // McastGrpLen: 32
				0x00, 0x00, 0x00, 0x00, // McastGrpAddr: 0.0.0.0
				0x20,                   // OriginatorLen: 32
				0x00, 0x00, 0x00, 0x00, // OriginatorAddr: 0.0.0.0
			},
			want: &SPMSI{
				RD:             &base.RD{Type: 0, Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				EthTag:         []byte{0x00, 0x00, 0x00, 0x00},
				McastSrcLen:    0,
				McastSrcAddr:   nil,
				McastGrpLen:    32,
				McastGrpAddr:   []byte{0x00, 0x00, 0x00, 0x00},
				OriginatorLen:  32,
				OriginatorAddr: []byte{0x00, 0x00, 0x00, 0x00},
			},
			wantErr: false,
		},
		{
			name:        "Invalid - Empty input",
			input:       []byte{},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Too short (19 bytes - below minimum)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00,       // McastSrcLen
				0x20,       // McastGrpLen
				0xef, 0x01, // Truncated McastGrpAddr (only 2 of 4 bytes)
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Truncated at RD",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, // Partial RD (only 4 bytes)
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Truncated at Ethernet Tag",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, // Partial EthTag (only 2 bytes)
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Truncated multicast source address",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD (8 bytes)
				0x00, 0x00, 0x00, 0x00, // EthTag (4 bytes)
				0x80, // McastSrcLen: 128 bits (expects 16 bytes)
				// Partial source (only 10 bytes of 16) to trigger truncation check at line 121
				0xc0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Total: 8+4+1+10 = 23 bytes (minimum), but source needs 16
			},
			wantErr:     true,
			errContains: "truncated multicast source address",
		},
		{
			name: "Invalid - Truncated originator address",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00,                   // McastSrcLen: 0 (no source)
				0x20,                   // McastGrpLen: 32 bits
				0xef, 0x01, 0x01, 0x01, // McastGrpAddr
				0x80,                                           // OriginatorLen: 128 bits (expects 16 bytes)
				0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Partial originator (only 8 of 16 bytes) - TRUNCATED
			},
			wantErr:     true,
			errContains: "truncated originator address",
		},
		{
			name: "Invalid - Invalid multicast source length (64 bits)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x40, // McastSrcLen: 64 bits (invalid - must be 0, 32, or 128)
				0xc0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, // 8 bytes
				0x20,                   // McastGrpLen: 32
				0xef, 0x01, 0x01, 0x01, // McastGrpAddr
				0x20,                   // OriginatorLen: 32
				0x0a, 0x00, 0x00, 0x01, // OriginatorAddr
			},
			wantErr:     true,
			errContains: "invalid multicast source length: 64 (must be 0, 32, or 128)",
		},
		{
			name: "Invalid - Invalid multicast group length (64 bits)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00, // McastSrcLen: 0
				0x40, // McastGrpLen: 64 bits (invalid - must be 32 or 128)
				0xef, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, // 8 bytes
				0x20,                   // OriginatorLen: 32
				0x0a, 0x00, 0x00, 0x01, // OriginatorAddr
			},
			wantErr:     true,
			errContains: "invalid multicast group length: 64 (must be 32 or 128)",
		},
		{
			name: "Invalid - Invalid originator length (64 bits)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00,                   // McastSrcLen: 0
				0x20,                   // McastGrpLen: 32
				0xef, 0x01, 0x01, 0x01, // McastGrpAddr
				0x40, // OriginatorLen: 64 bits (invalid - must be 32 or 128)
				0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 8 bytes
			},
			wantErr:     true,
			errContains: "invalid originator address length: 64 (must be 32 or 128)",
		},
		{
			name: "Invalid - Extra trailing bytes",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00,                   // McastSrcLen: 0
				0x20,                   // McastGrpLen: 32
				0xef, 0x01, 0x01, 0x01, // McastGrpAddr
				0x20,                   // OriginatorLen: 32
				0x0a, 0x00, 0x00, 0x01, // OriginatorAddr
				0xff, 0xff, // Extra bytes
			},
			wantErr:     true,
			errContains: "invalid length of S-PMSI A-D route: expected 23 bytes, have 25",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNSPMSI(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("UnmarshalEVPNSPMSI() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("UnmarshalEVPNSPMSI() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("UnmarshalEVPNSPMSI() unexpected error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalEVPNSPMSI() mismatch:\ngot  = %+v\nwant = %+v", got, tt.want)
			}
		})
	}
}

// TestRFC9572_SPMSIIntegration tests full EVPN NLRI parsing with Type 10 routes
func TestRFC9572_SPMSIIntegration(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantType    uint8
		wantLen     uint8
		wantRD      string
		wantEthTag  []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid EVPN NLRI - Type 10 IPv4 (S,G)",
			input: []byte{
				0x0a, // Route Type: 10 (S-PMSI A-D)
				0x1b, // Length: 27 bytes
				// RD Type 0: 0:100:200
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				// Ethernet Tag ID: 0
				0x00, 0x00, 0x00, 0x00,
				// Multicast Source: 32 bits, 192.0.2.1
				0x20, 0xc0, 0x00, 0x02, 0x01,
				// Multicast Group: 32 bits, 239.1.1.1
				0x20, 0xef, 0x01, 0x01, 0x01,
				// Originator: 32 bits, 10.0.0.1
				0x20, 0x0a, 0x00, 0x00, 0x01,
			},
			wantType:   10,
			wantLen:    27,
			wantRD:     "100:200",
			wantEthTag: []byte{0x00, 0x00, 0x00, 0x00},
			wantErr:    false,
		},
		{
			name: "Valid EVPN NLRI - Type 10 (*,G)",
			input: []byte{
				0x0a, // Route Type: 10 (S-PMSI A-D)
				0x17, // Length: 23 bytes
				// RD Type 1: 192.0.2.1:500
				0x00, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x01, 0xf4,
				// Ethernet Tag ID: 100
				0x00, 0x00, 0x00, 0x64,
				// Multicast Source: 0 bits (wildcard)
				0x00,
				// Multicast Group: 32 bits, 239.100.1.1
				0x20, 0xef, 0x64, 0x01, 0x01,
				// Originator: 32 bits, 172.16.0.1
				0x20, 0xac, 0x10, 0x00, 0x01,
			},
			wantType:   10,
			wantLen:    23,
			wantRD:     "192.0.2.1:500",
			wantEthTag: []byte{0x00, 0x00, 0x00, 0x64},
			wantErr:    false,
		},
		{
			name: "Invalid EVPN NLRI - Type 10 wrong length",
			input: []byte{
				0x0a, // Route Type: 10
				0x14, // Length: 20 bytes (incorrect - too short for minimum 23)
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x00, 0x00,
				0x00,
				0x20, 0xef, 0x01, 0x01, 0x01,
				// Missing originator fields
			},
			wantErr:     true,
			errContains: "need 20 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := UnmarshalEVPNNLRI(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("UnmarshalEVPNNLRI() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("UnmarshalEVPNNLRI() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("UnmarshalEVPNNLRI() unexpected error = %v", err)
				return
			}
			if len(route.Route) != 1 {
				t.Fatalf("UnmarshalEVPNNLRI() got %d routes, want 1", len(route.Route))
			}
			nlri := route.Route[0]
			if nlri.RouteType != tt.wantType {
				t.Errorf("RouteType = %d, want %d", nlri.RouteType, tt.wantType)
			}
			if nlri.Length != tt.wantLen {
				t.Errorf("Length = %d, want %d", nlri.Length, tt.wantLen)
			}
			spmsi, ok := nlri.RouteTypeSpec.(*SPMSI)
			if !ok {
				t.Fatalf("RouteTypeSpec is not *SPMSI")
			}
			if spmsi.RD.String() != tt.wantRD {
				t.Errorf("RD = %s, want %s", spmsi.RD.String(), tt.wantRD)
			}
			if !reflect.DeepEqual(spmsi.EthTag, tt.wantEthTag) {
				t.Errorf("EthTag = %v, want %v", spmsi.EthTag, tt.wantEthTag)
			}
		})
	}
}
