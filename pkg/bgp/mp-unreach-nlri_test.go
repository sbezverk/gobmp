package bgp

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalUnreachNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *MPUnReachNLRI
	}{
		{
			name:  "evpn unreach nlri update End of RIB",
			input: []byte{0x00, 0x19, 0x46},
			expect: &MPUnReachNLRI{
				AddressFamilyID:    25,
				SubAddressFamilyID: 70,
				EndOfRIB:           true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := UnmarshalMPUnReachNLRI(tt.input)
			if err != nil {
				t.Fatalf("failed to unmarshal MP Unreach NLRI with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, actual) {
				t.Logf("differences: %+v", deep.Equal(tt.expect, actual))
				t.Fatal("the expected object does not match the actual")
			}
		})
	}
}
