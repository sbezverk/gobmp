package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestPeerMessageAS4LocalASN(t *testing.T) {
	tests := []struct {
		name    string
		entries []*bgp.CapabilityData
		want    uint32
	}{
		{name: "two octet fallback", want: 65000},
		{name: "AS4 preferred", entries: []*bgp.CapabilityData{{Value: []byte{0xfa, 0x56, 0xea, 0}}}, want: 4200000000},
		{name: "malformed first fallback", entries: []*bgp.CapabilityData{{Value: []byte{1}}, {Value: []byte{0xfa, 0x56, 0xea, 0}}}, want: 65000},
		{name: "nil first fallback", entries: []*bgp.CapabilityData{nil}, want: 65000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProducer(&mockPublisher{}, false).(*producer)
			ph := makePeerHeader(t, bmp.PeerType0, 0)
			up := buildPeerUpMessage(t, "192.0.2.1")
			up.SentOpen.Capabilities = bgp.Capability{65: tt.entries}
			peer, err := p.producePeerMessage(peerUP, bmp.Message{PeerHeader: ph, Payload: up}, ph.Identity)
			if err != nil {
				t.Fatal(err)
			}
			if peer.LocalASN != tt.want {
				t.Fatalf("LocalASN=%d want %d", peer.LocalASN, tt.want)
			}
		})
	}
}
