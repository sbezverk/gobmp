package mup

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/base"
)

// The byte vectors below were produced by GoBGP's BGP-MUP serializer
// (pkg/packet/bgp/mup.go), which implements the same draft revision.

// rd returns the Route Distinguisher 100:100 used by every vector
func rd() *base.RD {
	return &base.RD{Type: 0, Value: []byte{0x00, 0x64, 0x00, 0x00, 0x00, 0x64}}
}

func v4(s string) []byte {
	return net.ParseIP(s).To4()
}

func v6(s string) []byte {
	return net.ParseIP(s).To16()
}

func u32(v uint32) *uint32 {
	return &v
}

func TestUnmarshalMUPNLRI(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		ipv6  bool
		want  *Route
	}{
		{
			name: "Interwork Segment Discovery IPv4",
			input: []byte{
				0x01, 0x00, 0x01, 0x0c, // arch 3gpp-5g, route type 1, length 12
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, // RD 100:100
				0x18,             // prefix length 24
				0x0a, 0x0a, 0x0a, // 10.10.10.0
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeISD,
				Length:           12,
				RouteTypeSpec: &ISDRoute{
					RD:           rd(),
					PrefixLength: 24,
					Prefix:       v4("10.10.10.0"),
				},
			}}},
		},
		{
			name: "Interwork Segment Discovery IPv6",
			input: []byte{
				0x01, 0x00, 0x01, 0x11,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40,                                           // prefix length 64
				0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 2001::/64
			},
			ipv6: true,
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeISD,
				Length:           17,
				RouteTypeSpec: &ISDRoute{
					RD:           rd(),
					PrefixLength: 64,
					Prefix:       v6("2001::"),
				},
			}}},
		},
		{
			name: "Direct Segment Discovery IPv4",
			input: []byte{
				0x01, 0x00, 0x02, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x0a, 0x0a, 0x01, // 10.10.10.1
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeDSD,
				Length:           12,
				RouteTypeSpec: &DSDRoute{
					RD:      rd(),
					Address: v4("10.10.10.1"),
				},
			}}},
		},
		{
			name: "Direct Segment Discovery IPv6",
			input: []byte{
				0x01, 0x00, 0x02, 0x18,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001::1
			},
			ipv6: true,
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeDSD,
				Length:           24,
				RouteTypeSpec: &DSDRoute{
					RD:      rd(),
					Address: v6("2001::1"),
				},
			}}},
		},
		{
			name: "Type 1 ST IPv4",
			input: []byte{
				0x01, 0x00, 0x03, 0x17,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18,             // prefix length 24
				0xc0, 0x64, 0x00, // 192.100.0.0
				0x00, 0x00, 0x00, 0x64, // TEID 100
				0x09,                   // QFI 9
				0x20,                   // endpoint address length 32
				0x0a, 0x0a, 0x0a, 0x01, // 10.10.10.1
				0x00, // source address length 0
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST1,
				Length:           23,
				RouteTypeSpec: &ST1Route{
					RD:                    rd(),
					PrefixLength:          24,
					Prefix:                v4("192.100.0.0"),
					TEID:                  100,
					QFI:                   9,
					EndpointAddressLength: 32,
					EndpointAddress:       v4("10.10.10.1"),
				},
			}}},
		},
		{
			name: "Type 1 ST IPv4 with Source Address",
			input: []byte{
				0x01, 0x00, 0x03, 0x1b,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18,
				0xc0, 0x64, 0x00,
				0x00, 0x00, 0x00, 0x64,
				0x09,
				0x20,
				0x0a, 0x0a, 0x0a, 0x01,
				0x20,                   // source address length 32
				0x0a, 0x0a, 0x0a, 0x02, // 10.10.10.2
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST1,
				Length:           27,
				RouteTypeSpec: &ST1Route{
					RD:                    rd(),
					PrefixLength:          24,
					Prefix:                v4("192.100.0.0"),
					TEID:                  100,
					QFI:                   9,
					EndpointAddressLength: 32,
					EndpointAddress:       v4("10.10.10.1"),
					SourceAddressLength:   32,
					SourceAddress:         v4("10.10.10.2"),
				},
			}}},
		},
		{
			name: "Type 1 ST IPv6 with Source Address",
			input: []byte{
				0x01, 0x00, 0x03, 0x36,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x30,                               // prefix length 48
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, // 2001:db8:1::
				0x00, 0x00, 0x00, 0x64,
				0x09,
				0x80, // endpoint address length 128
				0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001::1
				0x80, // source address length 128
				0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // 2001::2
			},
			ipv6: true,
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST1,
				Length:           54,
				RouteTypeSpec: &ST1Route{
					RD:                    rd(),
					PrefixLength:          48,
					Prefix:                v6("2001:db8:1::"),
					TEID:                  100,
					QFI:                   9,
					EndpointAddressLength: 128,
					EndpointAddress:       v6("2001::1"),
					SourceAddressLength:   128,
					SourceAddress:         v6("2001::2"),
				},
			}}},
		},
		{
			// No TLV applies to a Type 1 ST route, the framing is validated
			// and the TLV is then ignored.
			name: "Type 1 ST with unknown TLV",
			input: []byte{
				0x01, 0x00, 0x03, 0x1d,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18,
				0xc0, 0x64, 0x00,
				0x00, 0x00, 0x00, 0x64,
				0x09,
				0x20,
				0x0a, 0x0a, 0x0a, 0x01,
				0x00,
				0xc8, 0x04, 0xde, 0xad, 0xbe, 0xef, // TLV type 200
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST1,
				Length:           29,
				RouteTypeSpec: &ST1Route{
					RD:                    rd(),
					PrefixLength:          24,
					Prefix:                v4("192.100.0.0"),
					TEID:                  100,
					QFI:                   9,
					EndpointAddressLength: 32,
					EndpointAddress:       v4("10.10.10.1"),
				},
			}}},
		},
		{
			name: "Type 2 ST IPv4 TEID length 32",
			input: []byte{
				0x01, 0x00, 0x04, 0x11,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40,                   // endpoint length 64
				0x0a, 0x0a, 0x0a, 0x01, // 10.10.10.1
				0x00, 0x00, 0x00, 0x64, // TEID 100
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST2,
				Length:           17,
				RouteTypeSpec: &ST2Route{
					RD:              rd(),
					EndpointLength:  64,
					EndpointAddress: v4("10.10.10.1"),
					TEID:            u32(100),
				},
			}}},
		},
		{
			name: "Type 2 ST IPv4 TEID length 10",
			input: []byte{
				0x01, 0x00, 0x04, 0x0f,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x2a, // endpoint length 42, so 10 TEID bits
				0x0a, 0x0a, 0x0a, 0x01,
				0x64, 0x40,
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST2,
				Length:           15,
				RouteTypeSpec: &ST2Route{
					RD:              rd(),
					EndpointLength:  42,
					EndpointAddress: v4("10.10.10.1"),
					TEID:            u32(0x64400000),
				},
			}}},
		},
		{
			name: "Type 2 ST IPv4 TEID length 0",
			input: []byte{
				0x01, 0x00, 0x04, 0x0d,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x20, // endpoint length 32, no TEID
				0x0a, 0x0a, 0x0a, 0x01,
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST2,
				Length:           13,
				RouteTypeSpec: &ST2Route{
					RD:              rd(),
					EndpointLength:  32,
					EndpointAddress: v4("10.10.10.1"),
				},
			}}},
		},
		{
			name: "Type 2 ST IPv6 TEID length 10",
			input: []byte{
				0x01, 0x00, 0x04, 0x1b,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x8a, // endpoint length 138, so 10 TEID bits
				0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x64, 0x40,
			},
			ipv6: true,
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST2,
				Length:           27,
				RouteTypeSpec: &ST2Route{
					RD:              rd(),
					EndpointLength:  138,
					EndpointAddress: v6("2001::1"),
					TEID:            u32(0x64400000),
				},
			}}},
		},
		{
			name: "Type 2 ST with 3gpp-5g Session Parameters TLV",
			input: []byte{
				0x01, 0x00, 0x04, 0x18,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40,
				0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00, 0x64,
				0x01, 0x05, 0x00, 0x00, 0x00, 0xc8, 0x09, // TEID 200, QFI 9
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST2,
				Length:           24,
				RouteTypeSpec: &ST2Route{
					RD:              rd(),
					EndpointLength:  64,
					EndpointAddress: v4("10.10.10.1"),
					TEID:            u32(100),
					TLVs: []*TLV{
						{Type: TLVTypeSessionParameters, Length: 5, Value: []byte{0x00, 0x00, 0x00, 0xc8, 0x09}},
					},
				},
			}}},
		},
		{
			name: "Type 2 ST with all TLV types",
			input: []byte{
				0x01, 0x00, 0x04, 0x36,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40,
				0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00, 0x64,
				0x01, 0x05, 0x00, 0x00, 0x00, 0xc8, 0x09, // Session Parameters
				0x02, 0x04, 0x0a, 0x14, 0x1e, 0x28, // Interwork Endpoint 10.20.30.40
				0x03, 0x10, // Source Address 2001::100
				0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
				0xc8, 0x04, 0xde, 0xad, 0xbe, 0xef, // unknown type 200
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST2,
				Length:           54,
				RouteTypeSpec: &ST2Route{
					RD:              rd(),
					EndpointLength:  64,
					EndpointAddress: v4("10.10.10.1"),
					TEID:            u32(100),
					TLVs: []*TLV{
						{Type: TLVTypeSessionParameters, Length: 5, Value: []byte{0x00, 0x00, 0x00, 0xc8, 0x09}},
						{Type: TLVTypeInterworkEndpoint, Length: 4, Value: v4("10.20.30.40")},
						{Type: TLVTypeSourceAddress, Length: 16, Value: v6("2001::100")},
						{Type: 200, Length: 4, Value: []byte{0xde, 0xad, 0xbe, 0xef}},
					},
				},
			}}},
		},
		{
			name: "Type 2 ST with TLV after zero length TEID",
			input: []byte{
				0x01, 0x00, 0x04, 0x14,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x20,
				0x0a, 0x0a, 0x0a, 0x01,
				0x01, 0x05, 0x00, 0x00, 0x00, 0xc8, 0x09,
			},
			want: &Route{Route: []*NLRI{{
				ArchitectureType: ArchType3GPP5G,
				RouteType:        RouteTypeST2,
				Length:           20,
				RouteTypeSpec: &ST2Route{
					RD:              rd(),
					EndpointLength:  32,
					EndpointAddress: v4("10.10.10.1"),
					TLVs: []*TLV{
						{Type: TLVTypeSessionParameters, Length: 5, Value: []byte{0x00, 0x00, 0x00, 0xc8, 0x09}},
					},
				},
			}}},
		},
		{
			name: "Two NLRIs in one MP_REACH",
			input: []byte{
				0x01, 0x00, 0x02, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x0a, 0x0a, 0x01,
				0x01, 0x00, 0x01, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18, 0x0a, 0x0a, 0x0a,
			},
			want: &Route{Route: []*NLRI{
				{
					ArchitectureType: ArchType3GPP5G,
					RouteType:        RouteTypeDSD,
					Length:           12,
					RouteTypeSpec: &DSDRoute{
						RD:      rd(),
						Address: v4("10.10.10.1"),
					},
				},
				{
					ArchitectureType: ArchType3GPP5G,
					RouteType:        RouteTypeISD,
					Length:           12,
					RouteTypeSpec: &ISDRoute{
						RD:           rd(),
						PrefixLength: 24,
						Prefix:       v4("10.10.10.0"),
					},
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalMUPNLRI(tt.input, tt.ipv6, false)
			if err != nil {
				t.Fatalf("UnmarshalMUPNLRI() unexpected error: %+v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Logf("Differences: %+v", deep.Equal(tt.want, got))
				t.Fatalf("UnmarshalMUPNLRI() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestUnmarshalMUPNLRIErrors(t *testing.T) {
	// Only a common header that cannot be read, or a Length running past the
	// attribute, leaves no way to locate the next NLRI.
	tests := []struct {
		name   string
		input  []byte
		pathID bool
	}{
		{
			name:  "truncated common header",
			input: []byte{0x01, 0x00, 0x01},
		},
		{
			name: "route type specific length exceeds available data",
			input: []byte{
				0x01, 0x00, 0x02, 0x20,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x0a, 0x0a, 0x01,
			},
		},
		{
			name:   "Path Identifier expected but data too short",
			input:  []byte{0x00, 0x00, 0x00},
			pathID: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := UnmarshalMUPNLRI(tt.input, false, tt.pathID); err == nil {
				t.Fatal("UnmarshalMUPNLRI() expected an error, got none")
			}
		})
	}
}

// A malformed or unknown NLRI is treated as withdrawn and skipped, the
// attribute itself still decodes.
func TestUnmarshalMUPNLRISkipsMalformed(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		ipv6  bool
	}{
		{
			name: "unknown architecture type",
			input: []byte{
				0x02, 0x00, 0x02, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x0a, 0x0a, 0x01,
			},
		},
		{
			name: "unknown route type",
			input: []byte{
				0x01, 0x00, 0x05, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x0a, 0x0a, 0x01,
			},
		},
		{
			name: "invalid RD type",
			input: []byte{
				0x01, 0x00, 0x02, 0x0c,
				0x00, 0x03, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x0a, 0x0a, 0x01,
			},
		},
		{
			name: "ISD prefix length above the address family maximum",
			input: []byte{
				0x01, 0x00, 0x01, 0x0d,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x21, // 33 bits with AFI IPv4
				0x0a, 0x0a, 0x0a, 0x00,
			},
		},
		{
			// The common header Length covers the whole route type specific
			// field, a byte past the prefix is not padding.
			name: "ISD with a trailing byte",
			input: []byte{
				0x01, 0x00, 0x01, 0x0d,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18, 0x0a, 0x0a, 0x0a, 0x00,
			},
		},
		{
			name: "DSD address length does not match the AFI",
			input: []byte{
				0x01, 0x00, 0x02, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x0a, 0x0a, 0x01,
			},
			ipv6: true,
		},
		{
			name: "ST1 TEID 0",
			input: []byte{
				0x01, 0x00, 0x03, 0x17,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18, 0xc0, 0x64, 0x00,
				0x00, 0x00, 0x00, 0x00, // TEID 0
				0x09,
				0x20, 0x0a, 0x0a, 0x0a, 0x01,
				0x00,
			},
		},
		{
			name: "ST1 invalid endpoint address length",
			input: []byte{
				0x01, 0x00, 0x03, 0x17,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18, 0xc0, 0x64, 0x00,
				0x00, 0x00, 0x00, 0x64,
				0x09,
				0x40, // 64 is neither 32 nor 128
				0x0a, 0x0a, 0x0a, 0x01,
				0x00,
			},
		},
		{
			name: "ST1 invalid source address length",
			input: []byte{
				0x01, 0x00, 0x03, 0x17,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18, 0xc0, 0x64, 0x00,
				0x00, 0x00, 0x00, 0x64,
				0x09,
				0x20, 0x0a, 0x0a, 0x0a, 0x01,
				0x40, // 64 is neither 0, 32 nor 128
			},
		},
		{
			name: "ST1 single trailing octet cannot hold a TLV",
			input: []byte{
				0x01, 0x00, 0x03, 0x18,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18, 0xc0, 0x64, 0x00,
				0x00, 0x00, 0x00, 0x64,
				0x09,
				0x20, 0x0a, 0x0a, 0x0a, 0x01,
				0x00,
				0x01,
			},
		},
		{
			name: "ST2 full TEID 0",
			input: []byte{
				0x01, 0x00, 0x04, 0x11,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40, 0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00, 0x00, // TEID 0
			},
		},
		{
			// 10 TEID bits, all zero; only the padding bits are set.
			name: "ST2 partial TEID with zero significant bits",
			input: []byte{
				0x01, 0x00, 0x04, 0x0f,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x2a, 0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x3f,
			},
		},
		{
			name: "ST2 endpoint length below the endpoint address size",
			input: []byte{
				0x01, 0x00, 0x04, 0x0d,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x10, // 16 bits, below the 32 bit IPv4 endpoint address
				0x0a, 0x0a, 0x0a, 0x01,
			},
		},
		{
			name: "ST2 endpoint length above the maximum",
			input: []byte{
				0x01, 0x00, 0x04, 0x11,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x41, // 65 bits, above the 64 bit IPv4 maximum
				0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00, 0x64,
			},
		},
		{
			name: "ST2 route type specific length shorter than the mandatory fields",
			input: []byte{
				0x01, 0x00, 0x04, 0x10,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40, 0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00,
			},
		},
		{
			name: "ST2 single trailing octet cannot hold a TLV",
			input: []byte{
				0x01, 0x00, 0x04, 0x12,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40, 0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00, 0x64,
				0x01,
			},
		},
		{
			name: "ST2 TLV declared length exceeds remaining octets",
			input: []byte{
				0x01, 0x00, 0x04, 0x14,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40, 0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00, 0x64,
				0x01, 0x05, 0x00,
			},
		},
		{
			name: "ST2 Session Parameters TLV with invalid length",
			input: []byte{
				0x01, 0x00, 0x04, 0x17,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40, 0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00, 0x64,
				0x01, 0x04, 0x00, 0x00, 0x00, 0x64,
			},
		},
		{
			name: "ST2 Interwork Endpoint TLV with invalid length",
			input: []byte{
				0x01, 0x00, 0x04, 0x18,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40, 0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00, 0x64,
				0x02, 0x05, 0x0a, 0x14, 0x1e, 0x28, 0x00,
			},
		},
		{
			name: "ST2 Source Address TLV with invalid length",
			input: []byte{
				0x01, 0x00, 0x04, 0x18,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40, 0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00, 0x64,
				0x03, 0x05, 0x0a, 0x14, 0x1e, 0x28, 0x00,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalMUPNLRI(tt.input, tt.ipv6, false)
			if err != nil {
				t.Fatalf("UnmarshalMUPNLRI() unexpected error: %+v", err)
			}
			if len(got.Route) != 0 {
				t.Fatalf("UnmarshalMUPNLRI() decoded %d NLRIs, want the malformed one skipped", len(got.Route))
			}
		})
	}

	t.Run("valid NLRIs around a malformed one are kept", func(t *testing.T) {
		input := []byte{
			0x01, 0x00, 0x02, 0x0c, // DSD
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
			0x0a, 0x0a, 0x0a, 0x01,
			0x01, 0x00, 0x03, 0x17, // ST1 with TEID 0
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
			0x18, 0xc0, 0x64, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x09,
			0x20, 0x0a, 0x0a, 0x0a, 0x01,
			0x00,
			0x01, 0x00, 0x01, 0x0c, // ISD
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
			0x18, 0x0a, 0x0a, 0x0a,
		}
		got, err := UnmarshalMUPNLRI(input, false, false)
		if err != nil {
			t.Fatalf("UnmarshalMUPNLRI() unexpected error: %+v", err)
		}
		if len(got.Route) != 2 {
			t.Fatalf("UnmarshalMUPNLRI() decoded %d NLRIs, want 2", len(got.Route))
		}
		if got.Route[0].RouteType != RouteTypeDSD || got.Route[1].RouteType != RouteTypeISD {
			t.Fatalf("decoded route types %d, %d, want %d, %d", got.Route[0].RouteType, got.Route[1].RouteType, RouteTypeDSD, RouteTypeISD)
		}
	})
}

// Prefixes and the Type 2 ST TEID are bit length fields carried in whole
// octets, the padding bits are cleared so a sender that leaves them set does
// not change the published value.
func TestUnmarshalMUPNLRIMasksPadding(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  RouteTypeSpec
	}{
		{
			name: "ISD /25",
			input: []byte{
				0x01, 0x00, 0x01, 0x0d,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x19, 0x0a, 0x0a, 0x0a, 0xff,
			},
			want: &ISDRoute{RD: rd(), PrefixLength: 25, Prefix: v4("10.10.10.128")},
		},
		{
			name: "ST1 /25",
			input: []byte{
				0x01, 0x00, 0x03, 0x18,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x19, 0xc0, 0x64, 0x00, 0xff,
				0x00, 0x00, 0x00, 0x64,
				0x09,
				0x20, 0x0a, 0x0a, 0x0a, 0x01,
				0x00,
			},
			want: &ST1Route{
				RD:                    rd(),
				PrefixLength:          25,
				Prefix:                v4("192.100.0.128"),
				TEID:                  100,
				QFI:                   9,
				EndpointAddressLength: 32,
				EndpointAddress:       v4("10.10.10.1"),
			},
		},
		{
			name: "ST2 endpoint length 42",
			input: []byte{
				0x01, 0x00, 0x04, 0x0f,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x2a, 0x0a, 0x0a, 0x0a, 0x01,
				0x64, 0x7f,
			},
			want: &ST2Route{RD: rd(), EndpointLength: 42, EndpointAddress: v4("10.10.10.1"), TEID: u32(0x64400000)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalMUPNLRI(tt.input, false, false)
			if err != nil {
				t.Fatalf("UnmarshalMUPNLRI() unexpected error: %+v", err)
			}
			if len(got.Route) != 1 {
				t.Fatalf("UnmarshalMUPNLRI() decoded %d NLRIs, want 1", len(got.Route))
			}
			if !reflect.DeepEqual(got.Route[0].RouteTypeSpec, tt.want) {
				t.Logf("Differences: %+v", deep.Equal(tt.want, got.Route[0].RouteTypeSpec))
				t.Fatalf("UnmarshalMUPNLRI() = %+v, want %+v", got.Route[0].RouteTypeSpec, tt.want)
			}
		})
	}
}

func TestUnmarshalMUPNLRIEmpty(t *testing.T) {
	_, err := UnmarshalMUPNLRI([]byte{}, false, false)
	if !errors.Is(err, ErrEmptyNLRI) {
		t.Fatalf("UnmarshalMUPNLRI() error = %v, want %v", err, ErrEmptyNLRI)
	}
}

// Add Path prefixes every NLRI with a 4 octet Path Identifier, the same
// framing GoBGP applies to every address family in MP_REACH_NLRI.
func TestUnmarshalMUPNLRIAddPath(t *testing.T) {
	input := []byte{
		0x00, 0x00, 0x00, 0x01, // Path Identifier 1
		0x01, 0x00, 0x01, 0x0c,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
		0x18, 0x0a, 0x0a, 0x0a,
		0x00, 0x00, 0x00, 0x02, // Path Identifier 2
		0x01, 0x00, 0x01, 0x0c,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
		0x18, 0x0a, 0x0a, 0x14,
	}
	wantPathIDs := []uint32{1, 2}
	wantPrefix := []string{"10.10.10.0", "10.10.20.0"}

	got, err := UnmarshalMUPNLRI(input, false, true)
	if err != nil {
		t.Fatalf("UnmarshalMUPNLRI() unexpected error: %+v", err)
	}
	if len(got.Route) != len(wantPathIDs) {
		t.Fatalf("UnmarshalMUPNLRI() returned %d NLRIs, want %d", len(got.Route), len(wantPathIDs))
	}
	for i, n := range got.Route {
		if n.PathID != wantPathIDs[i] {
			t.Errorf("NLRI %d PathID = %d, want %d", i, n.PathID, wantPathIDs[i])
		}
		isd, ok := n.GetRouteTypeSpec().(*ISDRoute)
		if !ok {
			t.Fatalf("NLRI %d is %T, want *ISDRoute", i, n.GetRouteTypeSpec())
		}
		if got := net.IP(isd.Prefix).String(); got != wantPrefix[i] {
			t.Errorf("NLRI %d prefix = %s, want %s", i, got, wantPrefix[i])
		}
	}
}
