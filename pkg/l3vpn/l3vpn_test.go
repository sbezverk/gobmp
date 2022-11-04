package l3vpn

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalL3VPNNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *base.MPNLRI
		fail   bool
		srv6   bool
		pathID bool
	}{
		{
			name:  "nlri 1",
			input: []byte{120, 5, 220, 49, 0, 0, 2, 65, 0, 0, 253, 235, 3, 3, 3, 3},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{
								Value: 24003,
								Exp:   0,
								BoS:   true,
							},
						},
						RD: &base.RD{
							Type:  0,
							Value: []byte{2, 65, 0, 0, 253, 235},
						},
						Prefix: []byte{3, 3, 3, 3},
					},
				},
			},
			pathID: false,
			fail:   false,
		},
		{
			name:  "nlri 2",
			input: []byte{0x70, 0x05, 0xdc, 0x61, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, 0x01, 0x01, 0x64},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 24,
						Label: []*base.Label{
							{
								Value: 24006,
								Exp:   0,
								BoS:   true,
							},
						},
						RD: &base.RD{
							Type:  0,
							Value: []byte{0x00, 0x64, 0x00, 0x00, 0x00, 0x64},
						},
						Prefix: []byte{1, 1, 100},
					},
				},
			},
			pathID: false,
			fail:   false,
		},
		{
			name:  "nlri 4",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x78, 0x05, 0xdc, 0x41, 0x00, 0x00, 0x02, 0x41, 0x00, 0x00, 0xfd, 0x9a, 0x09, 0x16, 0x02, 0x16},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 32,
						Label: []*base.Label{
							{
								Value: 24004,
								Exp:   0,
								BoS:   true,
							},
						},
						RD: &base.RD{
							Type:  0,
							Value: []byte{0x02, 0x41, 0x00, 0x00, 0xfd, 0x9a},
						},
						Prefix: []byte{0x09, 0x16, 0x02, 0x16},
					},
				},
			},
			pathID: true,
			fail:   false,
		},
		{
			name:  "nlri 5 L3VPN IPv6",
			input: []byte{0x98, 0x18, 0xa8, 0xf1, 0x00, 0x00, 0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xd8, 0x18, 0xa8, 0xf1, 0x00, 0x00, 0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b, 0x01, 0x72, 0x00, 0x31, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xd0, 0x18, 0xa8, 0xf1, 0x00, 0x00, 0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b, 0x00, 0x10, 0x00, 0x00, 0x02, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 64,
						Label: []*base.Label{
							{
								Value: 101007,
								Exp:   0,
								BoS:   true,
							},
						},
						RD: &base.RD{
							Type:  0,
							Value: []byte{0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b},
						},
						Prefix: []byte{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
					},
					{
						Length: 128,
						Label: []*base.Label{
							{
								Value: 101007,
								Exp:   0,
								BoS:   true,
							},
						},
						RD: &base.RD{
							Type:  0,
							Value: []byte{0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b},
						},
						Prefix: []byte{0x01, 0x72, 0x00, 0x31, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
					},
					{
						Length: 120,
						Label: []*base.Label{
							{
								Value: 101007,
								Exp:   0,
								BoS:   true,
							},
						},
						RD: &base.RD{
							Type:  0,
							Value: []byte{0x02, 0x2b, 0x00, 0x00, 0x02, 0x2b},
						},
						Prefix: []byte{0x00, 0x10, 0x00, 0x00, 0x02, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					},
				},
			},
			pathID: false,
			fail:   false,
		},
		{
			name:  "srv6 based l3vpn",
			input: []byte{0x76, 0x00, 0x42, 0x00, 0x00, 0x00, 0x13, 0xce, 0x00, 0x00, 0xfe, 0x0a, 0x18, 0x18, 0x18, 0x00},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{
								Value: 16896,
								Exp:   0,
								BoS:   false,
							},
						},
						RD: &base.RD{
							Type:  0,
							Value: []byte{0x13, 0xce, 0x00, 0x00, 0xfe, 0x0a},
						},
						Prefix: []byte{0x18, 0x18, 0x18, 0x00},
					},
				},
			},
			fail:   false,
			srv6:   true,
			pathID: false,
		},
		{
			name:  "crash_11-02-2022",
			input: []byte{0x70, 0x05, 0xDC, 0x51, 0x00, 0x00, 0x02, 0xBC, 0x00, 0x00, 0x02, 0xBC, 0x0A, 0x46, 0x46},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 24,
						Label: []*base.Label{
							{
								Value: 24005,
								Exp:   0,
								BoS:   true,
							},
						},
						RD: &base.RD{
							Type:  0,
							Value: []byte{2, 188, 0, 0, 2, 188},
						},
						Prefix: []byte{10, 70, 70},
					},
				},
			},
			fail:   false,
			srv6:   false,
			pathID: true,
		},
		{
			name:  "crash_11-03-2022",
			input: []byte{0x77, 0x05, 0xDD, 0x31, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x07, 0x00, 0x01, 0xAC, 0x10, 0x07, 0x00, 0x70, 0x05, 0xDD, 0x31, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x07, 0x00, 0x01, 0x64, 0x64, 0x07},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{
								Value: 24019,
								Exp:   0,
								BoS:   true,
							},
						},
						RD: &base.RD{
							Type:  1,
							Value: []byte{10, 0, 0, 7, 0, 1},
						},
						Prefix: []byte{172, 16, 7, 0},
					},
					{
						Length: 24,
						Label: []*base.Label{
							{
								Value: 24019,
								Exp:   0,
								BoS:   true,
							},
						},
						RD: &base.RD{
							Type:  1,
							Value: []byte{10, 0, 0, 7, 0, 1},
						},
						Prefix: []byte{100, 100, 7},
					},
				},
			},
			fail:   false,
			srv6:   false,
			pathID: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalL3VPNNLRI(tt.input, tt.pathID, tt.srv6)
			if err != nil && !tt.fail {
				t.Fatalf("expected to succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatalf("expected to fail but succeeded")
			}
			if err == nil {
				if !reflect.DeepEqual(got, tt.expect) {
					t.Logf("Differences: %+v", deep.Equal(tt.expect, got))
					t.Fatal("test failed as expected nlri does not match actual nlri")
				}
			}
		})
	}
}
