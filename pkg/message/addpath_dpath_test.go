package message

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestNegotiatedAddPathDPathPublication(t *testing.T) {
	vpnFamily := bgp.AFISAFI{AFI: 1, SAFI: 128}
	dpath := []byte{1, 0, 0, 0xfd, 0xe8, 0, 1, 128}
	vpn := []byte{0, 0, 1, 0, 120, 0, 0, 0x31, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 192, 0, 2, 0}
	views := []struct {
		name          string
		flags         byte
		local, remote uint8
	}{
		{"in", 0, 1, 2},
		{"out", 0x10, 2, 1},
	}
	cases := []struct {
		name      string
		family    bgp.AFISAFI
		reach     bool
		dpath     []byte
		nlri      []byte
		action    string
		eor       bool
		malformed bool
	}{
		{"announcement", vpnFamily, true, dpath, vpn, "add", false, false},
		{"withdrawal", vpnFamily, false, dpath, vpn, "del", false, false},
		{"malformed announcement", vpnFamily, true, []byte{1, 0}, vpn, "del", false, true},
		{"empty MP_UNREACH with D-PATH", vpnFamily, false, dpath, nil, "", false, false},
		{"bare MP_UNREACH", vpnFamily, false, nil, nil, "del", true, false},
		// VPN parsing retries the opposite ADD-PATH mode. Unicast has no such
		// fallback, so this case detects loss of negotiated withdrawal state.
		{"unicast withdrawal", bgp.AFISAFI{AFI: 1, SAFI: 1}, false, dpath, []byte{0, 0, 1, 0, 24, 192, 0, 2}, "del", false, false},
	}
	for _, view := range views {
		for _, tt := range cases {
			t.Run(view.name+"/"+tt.name, func(t *testing.T) {
				attrs := dPathUnreach(tt.family.AFI, tt.family.SAFI, tt.nlri)
				if tt.reach {
					attrs = dPathReach(1, 128, []byte{0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1}, tt.nlri)
				}
				if tt.dpath != nil {
					attrs = append(dPathAttribute(36, tt.dpath), attrs...)
				}
				wire := append([]byte{0, 0, byte(len(attrs) >> 8), byte(len(attrs))}, attrs...)
				update, err := bgp.UnmarshalBGPUpdate(wire)
				if err != nil {
					t.Fatal(err)
				}
				pub := &recordingPublisher{}
				p := NewProducer(pub, true)
				up := buildPeerUpMessage(t, "192.0.2.1")
				up.SentOpen = addPathOpen(t, []bgp.AFISAFI{tt.family}, map[bgp.AFISAFI]uint8{tt.family: view.local})
				up.ReceivedOpen = addPathOpen(t, []bgp.AFISAFI{tt.family}, map[bgp.AFISAFI]uint8{tt.family: view.remote})
				queue := make(chan bmp.Message, 2)
				queue <- bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, 0), Payload: up}
				queue <- bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, view.flags), Payload: &bmp.RouteMonitor{Update: update}}
				close(queue)
				p.Producer(queue, nil)
				want := 2 // PeerUp followed by one route or genuine EOR.
				if tt.action == "" {
					want = 1
				}
				if len(pub.msgs) != want || pub.msgs[0].msgType != bmp.PeerStateChangeMsg {
					t.Fatalf("publications = %+v, want PeerUp and %d route messages", pub.msgs, want-1)
				}
				if want == 1 {
					return
				}
				wantType, wantLength := bmp.L3VPNV4Msg, int32(32)
				if tt.family.SAFI == 1 {
					wantType, wantLength = bmp.UnicastPrefixV4Msg, 24
				}
				if pub.msgs[1].msgType != wantType {
					t.Fatalf("message type = %d, want %d", pub.msgs[1].msgType, wantType)
				}
				var route L3VPNPrefix
				if err := json.Unmarshal(pub.msgs[1].payload, &route); err != nil {
					t.Fatal(err)
				}
				if route.Action != tt.action || route.IsEOR != tt.eor || route.IsAdjRIBOut != (view.flags == 0x10) {
					t.Fatalf("unexpected route action, EOR or direction: %+v", route)
				}
				if tt.eor {
					return
				}
				if route.PathID != 256 || route.Prefix != "192.0.2.0" || route.PrefixLen != wantLength {
					t.Errorf("route = %+v, want 192.0.2.0/%d with PathID 256", route, wantLength)
				}
				attrsGot := route.BaseAttributes
				if attrsGot == nil || !bytes.Equal(attrsGot.DPathAttr, tt.dpath) || attrsGot.DPathMalformed != tt.malformed || (attrsGot.DPath == nil) != tt.malformed {
					t.Errorf("D-PATH not preserved: %+v", attrsGot)
				}
			})
		}
	}
}
