package mcastvpn

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalMCASTVPNNLRI(t *testing.T) {
	rd1, _ := base.MakeRD([]byte{0x00, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x01})
	rd2, _ := base.MakeRD([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64})

	tests := []struct {
		name   string
		input  []byte
		expect *Route
		fail   bool
	}{
		{
			name: "Type 1 - Intra-AS I-PMSI A-D IPv4",
			input: []byte{
				0x01,                                           // Route Type 1
				0x0c,                                           // Length 12
				0x00, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x01, // RD Type 1
				0x0a, 0x00, 0x00, 0x01, // Originating Router IPv4 10.0.0.1
			},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 1,
						Length:    12,
						RouteTypeSpec: &Type1{
							RD:           rd1,
							OriginatorIP: []byte{0x0a, 0x00, 0x00, 0x01},
						},
					},
				},
			},
			fail: false,
		},
		{
			name: "Type 1 - Intra-AS I-PMSI A-D IPv6",
			input: []byte{
				0x01,                                           // Route Type 1
				0x18,                                           // Length 24
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, // RD Type 0
				// Originating Router IPv6 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 1,
						Length:    24,
						RouteTypeSpec: &Type1{
							RD: rd2,
							OriginatorIP: []byte{
								0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
							},
						},
					},
				},
			},
			fail: false,
		},
		{
			name: "Type 2 - Inter-AS I-PMSI A-D",
			input: []byte{
				0x02,                                           // Route Type 2
				0x0c,                                           // Length 12
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, // RD
				0x00, 0x00, 0xfd, 0xe8, // Source AS 65000
			},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 2,
						Length:    12,
						RouteTypeSpec: &Type2{
							RD:       rd2,
							SourceAS: 65000,
						},
					},
				},
			},
			fail: false,
		},
		{
			name: "Type 3 - S-PMSI A-D IPv4",
			input: []byte{
				0x03,                                           // Route Type 3
				0x16,                                           // Length 22 (8+1+4+1+4+4)
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, // RD (8 bytes)
				0x20,             // Multicast Source Length (32 bits)
				0xc0, 0xa8, 0x01, 0x01, // Multicast Source 192.168.1.1 (4 bytes)
				0x20,             // Multicast Group Length (32 bits)
				0xe0, 0x00, 0x00, 0x01, // Multicast Group 224.0.0.1 (4 bytes)
				0x0a, 0x00, 0x00, 0x01, // Originating Router 10.0.0.1 (4 bytes)
			},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 3,
						Length:    22,
						RouteTypeSpec: &Type3{
							RD:                 rd2,
							MulticastSourceLen: 32,
							MulticastSource:    []byte{0xc0, 0xa8, 0x01, 0x01},
							MulticastGroupLen:  32,
							MulticastGroup:     []byte{0xe0, 0x00, 0x00, 0x01},
							OriginatorIP:       []byte{0x0a, 0x00, 0x00, 0x01},
						},
					},
				},
			},
			fail: false,
		},
		{
			name: "Type 3 - S-PMSI A-D IPv6",
			input: []byte{
				0x03,                                           // Route Type 3
				0x3a,                                           // Length 58 (8+1+16+1+16+16)
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, // RD (8)
				0x80, // Multicast Source Length (128 bits)
				// Source 2001:db8:1::1 (16)
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x80, // Multicast Group Length (128 bits)
				// Group ff0e::1 (16)
				0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// Originating Router IPv6 2001:db8::2 (16)
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 3,
						Length:    58,
						RouteTypeSpec: &Type3{
							RD:                 rd2,
							MulticastSourceLen: 128,
							MulticastSource: []byte{
								0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
							},
							MulticastGroupLen: 128,
							MulticastGroup: []byte{
								0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
							},
							OriginatorIP: []byte{
								0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
							},
						},
					},
				},
			},
			fail: false,
		},
		{
			name: "Type 4 - Leaf A-D",
			input: []byte{
				0x04,                   // Route Type 4
				0x1a,                   // Length 26 (route key 22 + orig IP 4)
				// Route Key: Type 3 data without route type/length
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, // RD
				0x20,             // Source Length
				0xc0, 0xa8, 0x01, 0x01, // Source
				0x20,             // Group Length
				0xe0, 0x00, 0x00, 0x01, // Group
				0x0a, 0x00, 0x00, 0x01, // Originator (part of route key)
				0x0a, 0x00, 0x00, 0x02, // Originating Router IP for Type 4
			},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 4,
						Length:    26,
						RouteTypeSpec: &Type4{
							RouteKey: []byte{
								0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
								0x20, 0xc0, 0xa8, 0x01, 0x01,
								0x20, 0xe0, 0x00, 0x00, 0x01,
								0x0a, 0x00, 0x00, 0x01,
							},
							OriginatorIP: []byte{0x0a, 0x00, 0x00, 0x02},
						},
					},
				},
			},
			fail: false,
		},
		{
			name: "Type 5 - Source Active A-D",
			input: []byte{
				0x05,                                           // Route Type 5
				0x12,                                           // Length 18 (8+1+4+1+4)
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, // RD
				0x20,             // Multicast Source Length
				0xc0, 0xa8, 0x01, 0x01, // Multicast Source
				0x20,             // Multicast Group Length
				0xe0, 0x00, 0x00, 0x01, // Multicast Group
			},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 5,
						Length:    18,
						RouteTypeSpec: &Type5{
							RD:                 rd2,
							MulticastSourceLen: 32,
							MulticastSource:    []byte{0xc0, 0xa8, 0x01, 0x01},
							MulticastGroupLen:  32,
							MulticastGroup:     []byte{0xe0, 0x00, 0x00, 0x01},
						},
					},
				},
			},
			fail: false,
		},
		{
			name: "Type 6 - Shared Tree Join (C-multicast)",
			input: []byte{
				0x06,                                           // Route Type 6
				0x16,                                           // Length 22 (8+4+1+4+1+4)
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, // RD
				0x00, 0x00, 0xfd, 0xe8, // Source AS 65000
				0x20,             // Multicast Source Length (C-RP)
				0x00, 0x00, 0x00, 0x00, // Multicast Source (*, wildcard)
				0x20,             // Multicast Group Length
				0xe0, 0x00, 0x00, 0x01, // Multicast Group
			},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 6,
						Length:    22,
						RouteTypeSpec: &Type6{
							RD:                 rd2,
							SourceAS:           65000,
							MulticastSourceLen: 32,
							MulticastSource:    []byte{0x00, 0x00, 0x00, 0x00},
							MulticastGroupLen:  32,
							MulticastGroup:     []byte{0xe0, 0x00, 0x00, 0x01},
						},
					},
				},
			},
			fail: false,
		},
		{
			name: "Type 7 - Source Tree Join (C-multicast)",
			input: []byte{
				0x07,                                           // Route Type 7
				0x16,                                           // Length 22 (8+4+1+4+1+4)
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, // RD
				0x00, 0x00, 0xfd, 0xe8, // Source AS 65000
				0x20,             // Multicast Source Length (C-S)
				0xc0, 0xa8, 0x01, 0x01, // Multicast Source
				0x20,             // Multicast Group Length
				0xe0, 0x00, 0x00, 0x01, // Multicast Group
			},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 7,
						Length:    22,
						RouteTypeSpec: &Type7{
							RD:                 rd2,
							SourceAS:           65000,
							MulticastSourceLen: 32,
							MulticastSource:    []byte{0xc0, 0xa8, 0x01, 0x01},
							MulticastGroupLen:  32,
							MulticastGroup:     []byte{0xe0, 0x00, 0x00, 0x01},
						},
					},
				},
			},
			fail: false,
		},
		{
			name: "Multiple NLRIs - Type 1 and Type 3",
			input: []byte{
				// First NLRI: Type 1
				0x01, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x00, 0x00, 0x01,
				// Second NLRI: Type 3
				0x03, 0x16,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x20, 0xc0, 0xa8, 0x01, 0x01,
				0x20, 0xe0, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x01,
			},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 1,
						Length:    12,
						RouteTypeSpec: &Type1{
							RD:           rd2,
							OriginatorIP: []byte{0x0a, 0x00, 0x00, 0x01},
						},
					},
					{
						RouteType: 3,
						Length:    22,
						RouteTypeSpec: &Type3{
							RD:                 rd2,
							MulticastSourceLen: 32,
							MulticastSource:    []byte{0xc0, 0xa8, 0x01, 0x01},
							MulticastGroupLen:  32,
							MulticastGroup:     []byte{0xe0, 0x00, 0x00, 0x01},
							OriginatorIP:       []byte{0x0a, 0x00, 0x00, 0x01},
						},
					},
				},
			},
			fail: false,
		},
		{
			name:   "Empty NLRI",
			input:  []byte{},
			expect: nil,
			fail:   true,
		},
		{
			name: "Invalid route type",
			input: []byte{
				0x08, 0x0c, // Route Type 8 (invalid, only 1-7 defined)
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x00, 0x00, 0x01,
			},
			expect: nil,
			fail:   true,
		},
		{
			name: "Truncated Type 1 - missing originator IP",
			input: []byte{
				0x01, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x00, // Only 2 bytes instead of 4
			},
			expect: nil,
			fail:   true,
		},
		{
			name: "Type 1 - invalid originator IP length",
			input: []byte{
				0x01, 0x0b,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x00, 0x01, // 3 bytes (invalid, must be 4 or 16)
			},
			expect: nil,
			fail:   true,
		},
		{
			name: "Type 3 - prefix length not on byte boundary",
			input: []byte{
				0x03, 0x13, // Length 19 (8+1+3+1+4+2, non-standard but valid)
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18,       // 24 bits
				0xc0, 0xa8, 0x01, // 3 bytes for /24
				0x20,
				0xe0, 0x00, 0x00, 0x01,
				0x0a, 0x00, // Only 2 bytes remaining for originator (invalid)
			},
			expect: nil,
			fail:   true, // Changed to fail - invalid originator IP length
		},
		{
			name: "Truncated length field",
			input: []byte{
				0x01, // Route Type but missing length
			},
			expect: nil,
			fail:   true,
		},
		{
			name: "Length mismatch - declared length exceeds data",
			input: []byte{
				0x01, 0x0c,
				0x00, 0x00, 0x00, 0x64, // Only 6 bytes, but length says 12
			},
			expect: nil,
			fail:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalMCASTVPNNLRI(tt.input)
			if err != nil && !tt.fail {
				t.Fatalf("expected to succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatalf("expected to fail but succeeded")
			}
			if err == nil && !tt.fail {
				if !reflect.DeepEqual(got, tt.expect) {
					t.Logf("Differences: %+v", deep.Equal(tt.expect, got))
					t.Fatal("test failed as expected nlri does not match actual nlri")
				}
			}
		})
	}
}
