package evpn

import (
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalEVPNNLRIT3(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *NLRI
		rType  interface{}
	}{
		{
			name:  "real type 3 route nlri",
			input: []byte{0x03, 0x11, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x20, 0xac, 0x1f, 0x65, 0x06},
			expect: &NLRI{
				RouteType: 3,
				Length:    17,
				RouteTypeSpec: &InclusiveMulticastEthTag{
					RD: &base.RD{
						Type:  0,
						Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x00, 0x32},
					},
					EthTag:       nil,
					IPAddrLength: 32,
					IPAddr:       []byte{172, 31, 101, 6},
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
