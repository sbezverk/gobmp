package evpn

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// TestUnmarshalEVPNMcastMembershipReport tests RFC 9251 Section 9.2 Multicast Membership Report Synch Route parsing
func TestUnmarshalEVPNMcastMembershipReport(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		want        *McastMembershipReport
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid Type 7 - IPv4 (*,G), IPv4 originator, flags 0x0F",
			input: []byte{
				// RD Type 0 (8 bytes): 0:100:200
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				// ESI (10 bytes): all zeros (single-homed)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Ethernet Tag ID (4 bytes): 0
				0x00, 0x00, 0x00, 0x00,
				// Multicast Source Length (1 byte): 0 bits (wildcard)
				0x00,
				// No Multicast Source Address
				// Multicast Group Length (1 byte): 32 bits
				0x20,
				// Multicast Group Address (4 bytes): 239.1.1.1
				0xef, 0x01, 0x01, 0x01,
				// Originator Router Length (1 byte): 32 bits
				0x20,
				// Originator Router Address (4 bytes): 10.0.0.1
				0x0a, 0x00, 0x00, 0x01,
				// Flags (1 byte): 0x0F (all version flags set)
				0x0f,
			},
			want: &McastMembershipReport{
				RD: &base.RD{Type: 0, Value: []byte{0x00, 0x64, 0x00, 0x00, 0x00, 0xc8}},
				ESI: func() *ESI {
					esi, _ := MakeESI([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
					return esi
				}(),
				EthTag:            []byte{0x00, 0x00, 0x00, 0x00},
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
			name: "Valid Type 7 - IPv4 (S,G), IPv4 originator, non-zero ESI",
			input: []byte{
				// RD Type 1 (8 bytes): 192.0.2.1:500
				0x00, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x01, 0xf4,
				// ESI (10 bytes): Type 0 (arbitrary), value 0x0102030405060708090A
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
				// Ethernet Tag ID (4 bytes): 100
				0x00, 0x00, 0x00, 0x64,
				// Multicast Source Length (1 byte): 32 bits
				0x20,
				// Multicast Source Address (4 bytes): 192.0.2.10
				0xc0, 0x00, 0x02, 0x0a,
				// Multicast Group Length (1 byte): 32 bits
				0x20,
				// Multicast Group Address (4 bytes): 239.100.1.1
				0xef, 0x64, 0x01, 0x01,
				// Originator Router Length (1 byte): 32 bits
				0x20,
				// Originator Router Address (4 bytes): 172.16.0.1
				0xac, 0x10, 0x00, 0x01,
				// Flags (1 byte): 0x04 (v3 flag)
				0x04,
			},
			want: &McastMembershipReport{
				RD: &base.RD{Type: 1, Value: []byte{0xc0, 0x00, 0x02, 0x01, 0x01, 0xf4}},
				ESI: func() *ESI {
					esi, _ := MakeESI([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09})
					return esi
				}(),
				EthTag:            []byte{0x00, 0x00, 0x00, 0x64},
				McastSrcLen:       32,
				McastSrcAddr:      []byte{0xc0, 0x00, 0x02, 0x0a},
				McastGrpLen:       32,
				McastGrpAddr:      []byte{0xef, 0x64, 0x01, 0x01},
				OriginatorRtrLen:  32,
				OriginatorRtrAddr: []byte{0xac, 0x10, 0x00, 0x01},
				Flags:             0x04,
			},
			wantErr: false,
		},
		{
			name: "Valid Type 7 - IPv6 (S,G), IPv6 originator",
			input: []byte{
				// RD Type 2 (8 bytes): 65536:999
				0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x03, 0xe7,
				// ESI (10 bytes): Type 1 (LACP), value 0x11223344556677889900
				0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
				// Ethernet Tag ID (4 bytes): 999
				0x00, 0x00, 0x03, 0xe7,
				// Multicast Source Length (1 byte): 128 bits
				0x80,
				// Multicast Source Address (16 bytes): 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// Multicast Group Length (1 byte): 128 bits
				0x80,
				// Multicast Group Address (16 bytes): ff3e::5
				0xff, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				// Originator Router Length (1 byte): 128 bits
				0x80,
				// Originator Router Address (16 bytes): 2001:db8::100
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
				// Flags (1 byte): 0x02 (v2 flag)
				0x02,
			},
			want: &McastMembershipReport{
				RD: &base.RD{Type: 2, Value: []byte{0x00, 0x01, 0x00, 0x00, 0x03, 0xe7}},
				ESI: func() *ESI {
					esi, _ := MakeESI([]byte{0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99})
					return esi
				}(),
				EthTag:  []byte{0x00, 0x00, 0x03, 0xe7},
				McastSrcLen: 128,
				McastSrcAddr: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				McastGrpLen: 128,
				McastGrpAddr: []byte{0xff, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				OriginatorRtrLen: 128,
				OriginatorRtrAddr: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
				Flags: 0x02,
			},
			wantErr: false,
		},
		{
			name: "Valid Type 7 - Mixed IPv4 source, IPv6 group and originator",
			input: []byte{
				// RD Type 0 (8 bytes): 0:200:300
				0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x01, 0x2c,
				// ESI (10 bytes): zeros
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Ethernet Tag ID (4 bytes): 42
				0x00, 0x00, 0x00, 0x2a,
				// Multicast Source Length (1 byte): 32 bits
				0x20,
				// Multicast Source Address (4 bytes): 10.1.1.1
				0x0a, 0x01, 0x01, 0x01,
				// Multicast Group Length (1 byte): 128 bits
				0x80,
				// Multicast Group Address (16 bytes): ff3e::100
				0xff, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
				// Originator Router Length (1 byte): 128 bits
				0x80,
				// Originator Router Address (16 bytes): 2001:db8::200
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
				// Flags (1 byte): 0x01 (v1 flag)
				0x01,
			},
			want: &McastMembershipReport{
				RD: &base.RD{Type: 0, Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x01, 0x2c}},
				ESI: func() *ESI {
					esi, _ := MakeESI([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
					return esi
				}(),
				EthTag:       []byte{0x00, 0x00, 0x00, 0x2a},
				McastSrcLen:  32,
				McastSrcAddr: []byte{0x0a, 0x01, 0x01, 0x01},
				McastGrpLen:  128,
				McastGrpAddr: []byte{0xff, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
				OriginatorRtrLen: 128,
				OriginatorRtrAddr: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00},
				Flags: 0x01,
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
			name: "Invalid - Too short (33 bytes - below minimum)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ESI
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00,       // McastSrcLen
				0x20,       // McastGrpLen
				0xef, 0x01, 0x01, 0x01, // McastGrpAddr
				0x20, // OriginatorRtrLen
				// Missing originator address and flags
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
			name: "Invalid - Truncated at ESI",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, // Partial ESI (only 5 bytes)
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Truncated at Ethernet Tag",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ESI
				0x00, 0x00, // Partial EthTag (only 2 bytes)
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Truncated multicast source address (25 bytes total)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ESI
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x20,       // McastSrcLen: 32 bits (expects 4 bytes)
				0xc0, 0x00, // Partial source (only 2 of 4 bytes)
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Truncated multicast group address (26 bytes total)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ESI
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00,       // McastSrcLen: 0
				0x20,       // McastGrpLen: 32 bits
				0xef, 0x01, // Partial group (only 2 of 4 bytes)
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Truncated originator router address (31 bytes total)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ESI
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00,                   // McastSrcLen: 0
				0x20,                   // McastGrpLen: 32 bits
				0xef, 0x01, 0x01, 0x01, // McastGrpAddr
				0x20,       // OriginatorRtrLen: 32 bits
				0x0a, 0x00, // Partial originator (only 2 of 4 bytes)
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Missing flags byte (33 bytes total)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ESI
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00,                   // McastSrcLen: 0
				0x20,                   // McastGrpLen: 32 bits
				0xef, 0x01, 0x01, 0x01, // McastGrpAddr
				0x20,                   // OriginatorRtrLen: 32 bits
				0x0a, 0x00, 0x00, 0x01, // OriginatorRtrAddr
				// Missing flags byte
			},
			wantErr:     true,
			errContains: "invalid length",
		},
		{
			name: "Invalid - Invalid multicast source length (64 bits)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ESI
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x40, // McastSrcLen: 64 bits (invalid - must be 0, 32, or 128)
				0xc0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, // 8 bytes
				0x20,                   // McastGrpLen: 32
				0xef, 0x01, 0x01, 0x01, // McastGrpAddr
				0x20,                   // OriginatorRtrLen: 32
				0x0a, 0x00, 0x00, 0x01, // OriginatorRtrAddr
				0x0f, // Flags
			},
			wantErr:     true,
			errContains: "invalid multicast source length: 64 (must be 0, 32, or 128)",
		},
		{
			name: "Invalid - Invalid multicast group length (0 bits)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ESI
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00, // McastSrcLen: 0
				0x00, // McastGrpLen: 0 (invalid - must be 32 or 128)
				// Need enough bytes to pass minimum length check (34 bytes)
				// Add dummy group address (won't be read)
				0x00, 0x00, 0x00, 0x00, // Dummy McastGrpAddr
				0x20,                   // OriginatorRtrLen: 32
				0x0a, 0x00, 0x00, 0x01, // OriginatorRtrAddr
				0x0f, // Flags
			},
			wantErr:     true,
			errContains: "invalid multicast group length: 0 (must be 32 or 128)",
		},
		{
			name: "Invalid - Invalid originator length (16 bits)",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ESI
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00,                   // McastSrcLen: 0
				0x20,                   // McastGrpLen: 32
				0xef, 0x01, 0x01, 0x01, // McastGrpAddr
				0x10,                   // OriginatorRtrLen: 16 bits (invalid - must be 32 or 128)
				// Need enough bytes to pass minimum length check (34 bytes)
				0x0a, 0x00, 0x00, 0x00, // Dummy OriginatorRtrAddr (4 bytes to reach minimum)
				0x0f, // Flags
			},
			wantErr:     true,
			errContains: "invalid originator router length: 16 (must be 32 or 128)",
		},
		{
			name: "Invalid - Extra trailing bytes",
			input: []byte{
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ESI
				0x00, 0x00, 0x00, 0x00, // EthTag
				0x00,                   // McastSrcLen: 0
				0x20,                   // McastGrpLen: 32
				0xef, 0x01, 0x01, 0x01, // McastGrpAddr
				0x20,                   // OriginatorRtrLen: 32
				0x0a, 0x00, 0x00, 0x01, // OriginatorRtrAddr
				0x0f,       // Flags
				0xff, 0xff, // Extra bytes
			},
			wantErr:     true,
			errContains: "invalid length of Multicast Membership Report route: expected 34 bytes, have 36",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNMcastMembershipReport(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("UnmarshalEVPNMcastMembershipReport() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("UnmarshalEVPNMcastMembershipReport() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("UnmarshalEVPNMcastMembershipReport() unexpected error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalEVPNMcastMembershipReport() mismatch:\ngot  = %+v\nwant = %+v", got, tt.want)
			}
		})
	}
}

// TestRFC9251_McastMembershipReportIntegration tests full EVPN NLRI parsing with Type 7 routes
func TestRFC9251_McastMembershipReportIntegration(t *testing.T) {
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
			name: "Valid EVPN NLRI - Type 7 IPv4 (*,G)",
			input: []byte{
				0x07, // Route Type: 7 (Multicast Membership Report Synch)
				0x22, // Length: 34 bytes
				// RD Type 0: 0:100:200
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				// ESI: all zeros
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Ethernet Tag ID: 0
				0x00, 0x00, 0x00, 0x00,
				// Multicast Source: 0 bits (wildcard)
				0x00,
				// Multicast Group: 32 bits, 239.1.1.1
				0x20, 0xef, 0x01, 0x01, 0x01,
				// Originator: 32 bits, 10.0.0.1
				0x20, 0x0a, 0x00, 0x00, 0x01,
				// Flags: 0x0F
				0x0f,
			},
			wantType:   7,
			wantLen:    34,
			wantRD:     "100:200",
			wantEthTag: []byte{0x00, 0x00, 0x00, 0x00},
			wantErr:    false,
		},
		{
			name: "Valid EVPN NLRI - Type 7 IPv4 (S,G)",
			input: []byte{
				0x07, // Route Type: 7
				0x26, // Length: 38 bytes
				// RD Type 1: 192.0.2.1:500
				0x00, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x01, 0xf4,
				// ESI: Type 0, value 0x0102030405060708090A
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
				// Ethernet Tag ID: 100
				0x00, 0x00, 0x00, 0x64,
				// Multicast Source: 32 bits, 192.0.2.10
				0x20, 0xc0, 0x00, 0x02, 0x0a,
				// Multicast Group: 32 bits, 239.100.1.1
				0x20, 0xef, 0x64, 0x01, 0x01,
				// Originator: 32 bits, 172.16.0.1
				0x20, 0xac, 0x10, 0x00, 0x01,
				// Flags: 0x04
				0x04,
			},
			wantType:   7,
			wantLen:    38,
			wantRD:     "192.0.2.1:500",
			wantEthTag: []byte{0x00, 0x00, 0x00, 0x64},
			wantErr:    false,
		},
		{
			name: "Invalid EVPN NLRI - Type 7 wrong length",
			input: []byte{
				0x07, // Route Type: 7
				0x20, // Length: 32 bytes (incorrect - too short for minimum 34)
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00,
				0x20, 0xef, 0x01, 0x01, 0x01,
				// Missing originator and flags
			},
			wantErr:     true,
			errContains: "need 32 bytes",
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
			report, ok := nlri.RouteTypeSpec.(*McastMembershipReport)
			if !ok {
				t.Fatalf("RouteTypeSpec is not *McastMembershipReport")
			}
			if report.RD.String() != tt.wantRD {
				t.Errorf("RD = %s, want %s", report.RD.String(), tt.wantRD)
			}
			if !reflect.DeepEqual(report.EthTag, tt.wantEthTag) {
				t.Errorf("EthTag = %v, want %v", report.EthTag, tt.wantEthTag)
			}
		})
	}
}
