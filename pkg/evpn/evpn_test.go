package evpn

import (
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalEVPNNLRI(t *testing.T) {
	esi, _ := MakeESI([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	esi2, _ := MakeESI([]byte{0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10})
	mac, _ := MakeMACAddress([]byte{0x00, 0x81, 0xc4, 0xbc, 0x77, 0x8a})
	mac2, _ := MakeMACAddress([]byte{0x00, 0x81, 0xc4, 0xbc, 0x77, 0x8a})
	tests := []struct {
		name   string
		input  []byte
		expect *Route
	}{
		{
			name:  "real type 3 route nlri",
			input: []byte{0x03, 0x11, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x20, 0xac, 0x1f, 0x65, 0x06},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 3,
						Length:    17,
						RouteTypeSpec: &InclusiveMulticastEthTag{
							RD: &base.RD{
								Type:  0,
								Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x00, 0x32},
							},
							EthTag:       []byte{0, 0, 0, 0},
							IPAddrLength: 32,
							IPAddr:       []byte{172, 31, 101, 6},
						},
					},
				},
			},
		},
		{
			name:  "real type 2 route nlri",
			input: []byte{0x02, 0x21, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x81, 0xc4, 0xbc, 0x77, 0x8a, 0x00, 0x18, 0xa9, 0x71},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 2,
						Length:    33,
						RouteTypeSpec: &MACIPAdvertisement{
							RD: &base.RD{
								Type:  0,
								Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x00, 0x32},
							},
							ESI:           esi,
							EthTag:        []byte{0, 0, 0, 0},
							MACAddrLength: 48,
							MACAddr:       mac,
							IPAddrLength:  0,
							Label: []*base.Label{
								{
									Value: 101015,
									Exp:   0,
									BoS:   true,
								},
							},
						},
					},
				},
			},
		},
		{
			name:  "real type 3 route nlri",
			input: []byte{0x02, 0x28, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x81, 0xc4, 0xbc, 0x77, 0x8a, 0x20, 0x0a, 0x0a, 0x0a, 0x01, 0x18, 0xa9, 0x71, 0x18, 0xa9, 0x11, 0x02, 0x21, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x81, 0xc4, 0xbc, 0x77, 0x8a, 0x00, 0x18, 0xa9, 0x71},
			expect: &Route{
				Route: []*NLRI{
					{
						RouteType: 2,
						Length:    40,
						RouteTypeSpec: &MACIPAdvertisement{
							RD: &base.RD{
								Type:  0,
								Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x00, 0x32},
							},
							ESI:           esi2,
							EthTag:        []byte{0, 0, 0, 0},
							MACAddrLength: 48,
							MACAddr:       mac2,
							IPAddrLength:  32,
							IPAddr:        []byte{10, 10, 10, 1},
							Label: []*base.Label{
								{
									Value: 101015,
									Exp:   0,
									BoS:   true,
								},
								{
									Value: 101009,
									Exp:   0,
									BoS:   true,
								},
							},
						},
					},
					{
						RouteType: 2,
						Length:    33,
						RouteTypeSpec: &MACIPAdvertisement{
							RD: &base.RD{
								Type:  0,
								Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x00, 0x32},
							},
							ESI:           esi2,
							EthTag:        []byte{0, 0, 0, 0},
							MACAddrLength: 48,
							MACAddr:       mac2,
							IPAddrLength:  0,
							Label: []*base.Label{
								{
									Value: 101015,
									Exp:   0,
									BoS:   true,
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNNLRI(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}
		})
	}
}
