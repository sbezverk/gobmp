package message

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestRawDistinguisherSessionAndLocRIBIsolation(t *testing.T) {
	rd0, rd2 := []byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 1}, []byte{0, 2, 0, 0, 0xfd, 0xe8, 0, 1}
	cases := []struct {
		name     string
		peerType bmp.PeerType
		firstPD  []byte
		secondPD []byte
	}{
		{"opaque Loc-RIB distinguishers", bmp.PeerType3, []byte{0, 3, 0, 0, 0, 0, 0, 1}, []byte{0, 3, 0, 0, 0, 0, 0, 2}},
		{"Loc-RIB RD types", bmp.PeerType3, rd0, rd2},
		{"ordinary RD types", bmp.PeerType1, rd0, rd2},
	}
	family := bgp.AFISAFI{AFI: 1, SAFI: 1}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewProducer(&recordingPublisher{}, false).(*producer)
			first, second := makePeerHeader(t, tc.peerType, 0), makePeerHeader(t, tc.peerType, 0)
			first.PeerDistinguisher, second.PeerDistinguisher = tc.firstPD, tc.secondPD
			capable := addPathOpen(t, []bgp.AFISAFI{family}, map[bgp.AFISAFI]uint8{family: 3})
			plain := addPathOpen(t, []bgp.AFISAFI{family}, nil)
			for i, ph := range []*bmp.PerPeerHeader{first, second} {
				open := capable
				if i == 1 {
					open = plain
				}
				up := &bmp.PeerUpMessage{
					LocalAddress: make([]byte, 16), SentOpen: open, ReceivedOpen: open,
					Information: []bmp.InformationalTLV{{InformationType: 3, Information: []byte(fmt.Sprintf("VRF-%d", i))}},
				}
				p.producingWorker(bmp.Message{PeerHeader: ph, Payload: up, SpeakerIP: "192.0.2.1"})
			}
			if !p.addPathEnabled(first, family) || p.addPathEnabled(second, family) {
				t.Fatal("raw distinguishers shared ADD-PATH properties")
			}
			if len(p.identities) != 2 {
				t.Fatalf("cached identities = %d, want 2", len(p.identities))
			}
			checkAddPathRoute(t, p, first, family, true, "mp-add")
			checkAddPathRoute(t, p, second, family, false, "mp-add")
			if tc.peerType == bmp.PeerType3 {
				for i, ph := range []*bmp.PerPeerHeader{first, second} {
					want := fmt.Sprintf("VRF-%d", i)
					if got := p.getTableName(ph); got != want {
						t.Fatalf("PD %x table name = %q, want %q", ph.PeerDistinguisher, got, want)
					}
				}
			}
			p.producingWorker(bmp.Message{PeerHeader: second, Payload: &bmp.PeerDownMessage{}})
			if !p.addPathEnabled(first, family) || len(p.identities) != 1 {
				t.Fatal("PeerDown removed another distinguisher's properties or identity")
			}
			if tc.peerType == bmp.PeerType3 && (p.getTableName(first) != "VRF-0" || p.getTableName(second) != "") {
				t.Fatal("PeerDown removed another Loc-RIB's table name")
			}
		})
	}
}

func TestRawPeerKeysPreservePublishedRouteFields(t *testing.T) {
	// Snapshots from before raw cache-key changes preserve the public
	// identifiers while internal cache keys move to raw distinguisher bytes.
	cases := []struct {
		pd        []byte
		routeHash string
		peerHash  string
	}{
		{[]byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 1}, "67569f5318aa40c4eb9d1d75138fc1e8", "04648f72bd42aa0f573109334d01ea10"},
		{[]byte{0, 2, 0, 0, 0xfd, 0xe8, 0, 1}, "43daf0129c05aa6a48c057a4dc3945da", "97240dd22a530b89e695401f4d68dd1e"},
	}
	for _, tc := range cases {
		rec := &recordingPublisher{}
		p := NewProducer(rec, false).(*producer)
		ph := makePeerHeader(t, bmp.PeerType1, 0)
		ph.PeerDistinguisher = tc.pd
		update := &bgp.Update{NLRI: []byte{24, 192, 0, 2}, BaseAttributes: &bgp.BaseAttributes{}}
		p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: update}})
		if len(rec.msgs) != 1 {
			t.Fatalf("published route count = %d, want 1", len(rec.msgs))
		}
		var route UnicastPrefix
		if err := json.Unmarshal(rec.msgs[0].payload, &route); err != nil {
			t.Fatal(err)
		}
		if route.Hash != tc.routeHash || route.PeerHash != tc.peerHash {
			t.Fatalf("PD %x: public hashes changed: route=%s peer=%s", tc.pd, route.Hash, route.PeerHash)
		}
		peer, err := p.producePeerMessage(peerUP, bmp.Message{PeerHeader: ph, Payload: buildPeerUpMessage(t, "192.0.2.1")}, ph.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if peer.PeerRD != "65000:1" {
			t.Fatalf("published peer_rd = %q, want 65000:1", peer.PeerRD)
		}
	}
}
