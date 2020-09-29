package bgp

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalBGPOpenMessage(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *OpenMessage
		fail   bool
	}{
		{
			name:  "valid",
			input: []byte{0, 91, 1, 4, 19, 206, 0, 90, 192, 168, 8, 8, 62, 2, 6, 1, 4, 0, 1, 0, 1, 2, 6, 1, 4, 0, 1, 0, 4, 2, 6, 1, 4, 0, 1, 0, 128, 2, 2, 128, 0, 2, 2, 2, 0, 2, 6, 65, 4, 0, 0, 19, 206, 2, 20, 5, 18, 0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2},
			expect: &OpenMessage{
				Length:  91,
				Type:    1,
				Version: 4,
				MyAS:    5070, HoldTime: 90,
				BGPID:              []byte{192, 168, 8, 8},
				OptParamLen:        62,
				OptionalParameters: []InformationalTLV{},
				Capabilities: Capability{
					1: []*capabilityData{
						{
							Description: "Multiprotocol Extensions for BGP-4 : afi=1 safi=1 Unicast IPv4",
							Value:       []byte{0, 1, 0, 1},
						},
						{
							Description: "Multiprotocol Extensions for BGP-4 : afi=1 safi=4 MPLS Labels IPv4",
							Value:       []byte{0, 1, 0, 4},
						},
						{
							Description: "Multiprotocol Extensions for BGP-4 : afi=1 safi=128 MPLS-labeled VPN IPv4",
							Value:       []byte{0, 1, 0, 128},
						},
					},
					2: []*capabilityData{
						{
							Description: "Route Refresh Capability for BGP-4",
							Value:       []byte{},
						},
					},
					5: []*capabilityData{
						{
							Description: "Extended Next Hop Encoding",
							Value:       []byte{0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2},
						},
					},
					65: []*capabilityData{
						{
							Description: "Support for 4-octet AS number capability",
							Value:       []byte{0, 0, 19, 206},
						},
					},
					128: []*capabilityData{
						{
							Description: "Prestandard Route Refresh (deprecated)",
							Value:       []byte{},
						},
					},
				},
			},
			fail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := UnmarshalBGPOpenMessage(tt.input)
			if err != nil {
				if !tt.fail {
					t.Fatal("expected to succeed but failed")
				}
			}
			if err == nil {
				if tt.fail {
					t.Fatal("expected to fail but succeeded")
				}
			}
			if !reflect.DeepEqual(message, tt.expect) {
				t.Error("unmarshaled and expected messages do not much")
				t.Errorf("Diffs: %+v", deep.Equal(message, tt.expect))
			}
		})
	}
}
