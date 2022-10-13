package bmp

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/bgp"
)

func TestPeerUpMsg(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		remotePeerIPv6 bool
		expect         *PeerUpMessage
	}{
		{
			name:  "panic 1",
			input: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x5B, 0x01, 0x04, 0xC3, 0xCB, 0x00, 0x00, 0x01, 0x01, 0x0A, 0x01, 0x3E, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x04, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xC3, 0xCB, 0x02, 0x14, 0x05, 0x12, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01, 0x00, 0x80, 0x00, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x5B, 0x01, 0x04, 0xC3, 0xCB, 0x00, 0x00, 0x01, 0x01, 0x0A, 0x01, 0x3E, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x04, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xC3, 0xCB, 0x02, 0x14, 0x05, 0x12, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01, 0x00, 0x80, 0x00, 0x02, 0x00, 0x03, 0x00, 0x06, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C},
			expect: &PeerUpMessage{
				LocalAddress: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				LocalPort:    0,
				RemotePort:   0,
				SentOpen: &bgp.OpenMessage{
					Type:               1,
					Length:             91,
					Version:            4,
					MyAS:               50123,
					BGPID:              []byte{1, 1, 10, 1},
					OptParamLen:        62,
					OptionalParameters: []bgp.InformationalTLV{},
					Capabilities: bgp.Capability{
						1: []*bgp.CapabilityData{
							{
								Value:       []byte{0, 1, 0, 1},
								Description: "Multiprotocol Extensions for BGP-4 : afi=1 safi=1 Unicast IPv4",
							},
							{
								Value:       []byte{0, 1, 0, 4},
								Description: "Multiprotocol Extensions for BGP-4 : afi=1 safi=4 MPLS Labels IPv4",
							},
							{
								Value:       []byte{0, 1, 0, 128},
								Description: "Multiprotocol Extensions for BGP-4 : afi=1 safi=128 MPLS-labeled VPN IPv4",
							},
						},
						2: []*bgp.CapabilityData{
							{
								Value:       []byte{},
								Description: "Route Refresh Capability for BGP-4",
							},
						},
						5: []*bgp.CapabilityData{
							{
								Value:       []byte{0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2},
								Description: "Extended Next Hop Encoding",
							},
						},
						65: []*bgp.CapabilityData{
							{
								Value:       []byte{0, 0, 195, 203},
								Description: "Support for 4-octet AS number capability",
							},
						},
						128: []*bgp.CapabilityData{
							{
								Value:       []byte{},
								Description: "Prestandard Route Refresh (deprecated)",
							},
						},
					},
				},
				ReceivedOpen: &bgp.OpenMessage{
					Type:               1,
					Length:             91,
					Version:            4,
					MyAS:               50123,
					BGPID:              []byte{1, 1, 10, 1},
					OptParamLen:        62,
					OptionalParameters: []bgp.InformationalTLV{},
					Capabilities: bgp.Capability{
						1: []*bgp.CapabilityData{
							{
								Value:       []byte{0, 1, 0, 1},
								Description: "Multiprotocol Extensions for BGP-4 : afi=1 safi=1 Unicast IPv4",
							},
							{
								Value:       []byte{0, 1, 0, 4},
								Description: "Multiprotocol Extensions for BGP-4 : afi=1 safi=4 MPLS Labels IPv4",
							},
							{
								Value:       []byte{0, 1, 0, 128},
								Description: "Multiprotocol Extensions for BGP-4 : afi=1 safi=128 MPLS-labeled VPN IPv4",
							},
						},
						2: []*bgp.CapabilityData{
							{
								Value:       []byte{},
								Description: "Route Refresh Capability for BGP-4",
							},
						},
						5: []*bgp.CapabilityData{
							{
								Value:       []byte{0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2},
								Description: "Extended Next Hop Encoding",
							},
						},
						65: []*bgp.CapabilityData{
							{
								Value:       []byte{0, 0, 195, 203},
								Description: "Support for 4-octet AS number capability",
							},
						},
						128: []*bgp.CapabilityData{
							{
								Value:       []byte{},
								Description: "Prestandard Route Refresh (deprecated)",
							},
						},
					},
				},
				Information: []InformationalTLV{
					{
						InformationType:   3,
						InformationLength: 6,
						Information:       []byte{103, 108, 111, 98, 97, 108},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peerUp, err := UnmarshalPeerUpMessage(tt.input, tt.remotePeerIPv6)
			if err != nil {
				t.Fatalf("failed but supposed to succeed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, peerUp) {
				t.Logf("differences: %+v", deep.Equal(tt.expect, peerUp))
				t.Fatal("expected PeerUp message does not match the unmarshaled one")
			}
		})
	}
}
