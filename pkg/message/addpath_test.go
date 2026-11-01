package message

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func addPathOpen(t *testing.T, families []bgp.AFISAFI, modes map[bgp.AFISAFI]uint8) *bgp.OpenMessage {
	t.Helper()
	var capabilities []byte
	for _, family := range families {
		capabilities = append(capabilities, 1, 4, byte(family.AFI>>8), byte(family.AFI), 0, family.SAFI)
	}
	if len(modes) != 0 {
		capabilities = append(capabilities, 69, byte(4*len(modes)))
		for family, mode := range modes {
			capabilities = append(capabilities, byte(family.AFI>>8), byte(family.AFI), family.SAFI, mode)
		}
	}
	var optional []byte
	if len(capabilities) != 0 {
		optional = append([]byte{2, byte(len(capabilities))}, capabilities...)
	}
	wire := []byte{0, byte(29 + len(optional)), 1, 4, 0xfd, 0xe8, 0, 90, 10, 0, 0, 1, byte(len(optional))}
	open, err := bgp.UnmarshalBGPOpenMessage(append(wire, optional...))
	if err != nil {
		t.Fatalf("UnmarshalBGPOpenMessage: %v", err)
	}
	return open
}

func addPathPeerUp(t *testing.T, p *producer, ph *bmp.PerPeerHeader, local, remote *bgp.OpenMessage) {
	t.Helper()
	up := &bmp.PeerUpMessage{
		LocalAddress: make([]byte, 16), SentOpen: local, ReceivedOpen: remote,
		Information: []bmp.InformationalTLV{{InformationType: 3, Information: []byte("VRF-A")}},
	}
	if _, err := p.producePeerMessage(peerUP, bmp.Message{PeerHeader: ph, Payload: up}, ph.Identity); err != nil {
		t.Fatal(err)
	}
}

func addPathPeerDown(t *testing.T, p *producer, ph *bmp.PerPeerHeader) {
	t.Helper()
	if _, err := p.producePeerMessage(peerDown, bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{}}, ph.Identity); err != nil {
		t.Fatal(err)
	}
}

func TestAddPathNegotiationDirections(t *testing.T) {
	family := bgp.AFISAFI{AFI: 1, SAFI: 1}
	for local := uint8(0); local <= 3; local++ {
		for remote := uint8(0); remote <= 3; remote++ {
			t.Run(fmt.Sprintf("local%d_remote%d", local, remote), func(t *testing.T) {
				p := NewProducer(&recordingPublisher{}, false).(*producer)
				ph := makePeerHeader(t, bmp.PeerType0, 0)
				addPathPeerUp(t, p, ph, addPathOpen(t, nil, map[bgp.AFISAFI]uint8{family: local}), addPathOpen(t, nil, map[bgp.AFISAFI]uint8{family: remote}))
				for _, flags := range []byte{0, 0x40, 0x10, 0x50, 0x20, 0x60, 0x30, 0x70} {
					routePeer := makePeerHeader(t, bmp.PeerType0, flags)
					want := (local == 1 || local == 3) && (remote == 2 || remote == 3)
					if flags&0x10 != 0 {
						want = (local == 2 || local == 3) && (remote == 1 || remote == 3)
					}
					if got := p.addPathEnabled(routePeer, family); got != want {
						t.Errorf("flags 0x%x: ADD-PATH = %v, want %v", flags, got, want)
					}
				}
				addPathPeerDown(t, p, ph)
				if p.addPathEnabled(ph, family) || p.addPathEnabled(makePeerHeader(t, bmp.PeerType0, 0x10), family) {
					t.Error("PeerDown did not clear both directions")
				}
			})
		}
	}
}

func TestAddPathSessionIsolation(t *testing.T) {
	family := bgp.AFISAFI{AFI: 1, SAFI: 1}
	for _, changed := range []string{"address", "asn", "type", "distinguisher"} {
		t.Run(changed, func(t *testing.T) {
			p := NewProducer(&recordingPublisher{}, false).(*producer)
			first, second := makePeerHeader(t, bmp.PeerType0, 0), makePeerHeader(t, bmp.PeerType0, 0)
			switch changed {
			case "address":
				second.PeerAddress[15] = 2
			case "asn":
				second.PeerAS++
			case "type":
				second.PeerType = bmp.PeerType1
			case "distinguisher":
				first.PeerType, second.PeerType = bmp.PeerType1, bmp.PeerType1
				second.PeerDistinguisher[7] = 2
			}
			capable, plain := addPathOpen(t, nil, map[bgp.AFISAFI]uint8{family: 3}), addPathOpen(t, nil, nil)
			addPathPeerUp(t, p, first, capable, capable)
			addPathPeerUp(t, p, second, plain, plain)
			if !p.addPathEnabled(first, family) || p.addPathEnabled(second, family) {
				t.Fatal("different sessions overwrote each other's capabilities")
			}
			addPathPeerDown(t, p, second)
			if !p.addPathEnabled(first, family) {
				t.Fatal("PeerDown removed a different session")
			}
			addPathPeerUp(t, p, first, plain, plain)
			if p.addPathEnabled(first, family) {
				t.Fatal("renegotiation retained stale ADD-PATH")
			}
		})
	}
}

func TestAddPathFamilyIsolation(t *testing.T) {
	families := []bgp.AFISAFI{{AFI: 1, SAFI: 133}, {AFI: 2, SAFI: 133}, {AFI: 1, SAFI: 134}, {AFI: 2, SAFI: 134}, {AFI: 500, SAFI: 200}, {AFI: 501, SAFI: 200}}
	for _, enabled := range families {
		p := NewProducer(&recordingPublisher{}, false).(*producer)
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		open := addPathOpen(t, families, map[bgp.AFISAFI]uint8{enabled: 3})
		addPathPeerUp(t, p, ph, open, open)
		for _, family := range families {
			attribute := []byte{byte(family.AFI >> 8), byte(family.AFI), family.SAFI}
			got := p.mpAddPathCapability(ph, attribute)
			if got[bgp.NLRIMessageType(family.AFI, family.SAFI)] != (family == enabled) {
				t.Fatalf("enabled %v leaked into family %v: %v", enabled, family, got)
			}
		}
	}
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	for _, short := range [][]byte{nil, {0}, {0, 1}} {
		if got := p.mpAddPathCapability(nil, short); got != nil {
			t.Errorf("short attribute capabilities = %v, want nil", got)
		}
	}
	if p.addPathEnabled(nil, bgp.AFISAFI{AFI: 1, SAFI: 1}) {
		t.Error("missing peer enabled ADD-PATH")
	}
}

func TestLocRIBAddPathModesAndFamilyUpdates(t *testing.T) {
	v4, v6 := bgp.AFISAFI{AFI: 1, SAFI: 1}, bgp.AFISAFI{AFI: 2, SAFI: 1}
	for _, mode := range []uint8{1, 2, 3} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			p := NewProducer(&recordingPublisher{}, false).(*producer)
			ph := makePeerHeader(t, bmp.PeerType3, 0)
			v4Open := addPathOpen(t, []bgp.AFISAFI{v4}, map[bgp.AFISAFI]uint8{v4: mode})
			addPathPeerUp(t, p, ph, v4Open, v4Open)
			v6Open := addPathOpen(t, nil, map[bgp.AFISAFI]uint8{v6: mode})
			addPathPeerUp(t, p, ph, v6Open, v6Open)
			if !p.addPathEnabled(ph, v4) || !p.addPathEnabled(ph, v6) {
				t.Fatal("Loc-RIB discarded a separately announced family or mode")
			}
			plainV4 := addPathOpen(t, []bgp.AFISAFI{v4}, nil)
			addPathPeerUp(t, p, ph, plainV4, plainV4)
			if p.addPathEnabled(ph, v4) || !p.addPathEnabled(ph, v6) {
				t.Fatal("Loc-RIB did not replace only the repeated family")
			}
			checkAddPathRoute(t, p, ph, v4, false, "mp-add")
			checkAddPathRoute(t, p, ph, v6, true, "mp-add")
			if got := p.getTableName(ph); got != "VRF-A" {
				t.Fatalf("Loc-RIB table name = %q, want VRF-A", got)
			}
			ordinary := makePeerHeader(t, bmp.PeerType0, 0)
			addPathPeerUp(t, p, ordinary, plainV4, plainV4)
			addPathPeerDown(t, p, ordinary)
			if got := p.getTableName(ph); got != "VRF-A" {
				t.Fatalf("ordinary peer changed Loc-RIB table name to %q", got)
			}
			addPathPeerDown(t, p, ph)
			if p.addPathEnabled(ph, v6) || p.getTableName(ph) != "" {
				t.Fatal("Loc-RIB PeerDown did not clear capabilities and table name")
			}
		})
	}
}

func checkAddPathRoute(t *testing.T, p *producer, ph *bmp.PerPeerHeader, family bgp.AFISAFI, enabled bool, kind string) {
	t.Helper()
	nlri := []byte{24, 192, 0, 2}
	wantPrefix, wantLength := "192.0.2.0", int32(24)
	if family.AFI == 2 {
		nlri, wantPrefix, wantLength = []byte{32, 0x20, 1, 0x0d, 0xb8}, "2001:db8::", 32
	}
	wantPath := int32(0)
	if enabled {
		nlri, wantPath = append([]byte{0, 0, 1, 0}, nlri...), 256
	}
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}
	var got []*UnicastPrefix
	if kind == "legacy-add" || kind == "legacy-del" {
		op := AddPrefix
		update.NLRI = nlri
		if kind == "legacy-del" {
			op, update.WithdrawnRoutes = DelPrefix, nlri
		}
		var err error
		got, err = p.nlri(op, ph, update)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		attribute := []byte{byte(family.AFI >> 8), byte(family.AFI), family.SAFI}
		attrType := uint8(bgp.MP_UNREACH_NLRI)
		if kind == "mp-add" {
			attrType = bgp.MP_REACH_NLRI
			nextHop := net.ParseIP("10.0.0.1").To4()
			if family.AFI == 2 {
				nextHop = net.ParseIP("2001:db8::1").To16()
			}
			attribute = append(attribute, byte(len(nextHop)))
			attribute = append(attribute, nextHop...)
			attribute = append(attribute, 0)
		}
		attribute = append(attribute, nlri...)
		attrs := append([]byte{0x80, attrType, byte(len(attribute))}, attribute...)
		wire := make([]byte, 4)
		binary.BigEndian.PutUint16(wire[2:], uint16(len(attrs)))
		var err error
		update, err = bgp.UnmarshalBGPUpdate(append(wire, attrs...))
		if err != nil {
			t.Fatal(err)
		}
		rec := p.publisher.(*recordingPublisher)
		rec.msgs = nil
		p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: update}})
		for _, msg := range rec.msgs {
			var route UnicastPrefix
			if err := json.Unmarshal(msg.payload, &route); err != nil {
				t.Fatal(err)
			}
			got = append(got, &route)
		}
	}
	if len(got) != 1 || got[0].PathID != wantPath || got[0].Prefix != wantPrefix || got[0].PrefixLen != wantLength {
		t.Fatalf("%s enabled=%v routes=%+v, want one %s/%d PathID=%d", kind, enabled, got, wantPrefix, wantLength, wantPath)
	}
}

func TestNegotiatedAddPathWireParsing(t *testing.T) {
	family := bgp.AFISAFI{AFI: 1, SAFI: 1}
	for _, modes := range [][2]uint8{{1, 2}, {2, 1}} {
		for _, flags := range []byte{0, 0x10} {
			for _, kind := range []string{"legacy-add", "legacy-del", "mp-add", "mp-del"} {
				t.Run(fmt.Sprintf("local%d_remote%d_flags%x_%s", modes[0], modes[1], flags, kind), func(t *testing.T) {
					p := NewProducer(&recordingPublisher{}, false).(*producer)
					addPathPeerUp(t, p, makePeerHeader(t, bmp.PeerType0, 0), addPathOpen(t, nil, map[bgp.AFISAFI]uint8{family: modes[0]}), addPathOpen(t, nil, map[bgp.AFISAFI]uint8{family: modes[1]}))
					enabled := modes[0] == 1 && flags == 0 || modes[0] == 2 && flags == 0x10
					checkAddPathRoute(t, p, makePeerHeader(t, bmp.PeerType0, flags), family, enabled, kind)
				})
			}
		}
	}
}

func TestConcurrentPeerAddPathUpdates(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	ph := makePeerHeader(t, bmp.PeerType3, 0)
	family := bgp.AFISAFI{AFI: 1, SAFI: 1}
	open := addPathOpen(t, []bgp.AFISAFI{family}, map[bgp.AFISAFI]uint8{family: 1})
	up := &bmp.PeerUpMessage{SentOpen: open, ReceivedOpen: open}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				p.setPeerProperties(ph, up)
				p.addPathEnabled(ph, family)
				p.mpAddPathCapability(ph, []byte{0, 1, 1})
				p.getTableName(ph)
				addPathPeerDown(t, p, ph)
			}
		}()
	}
	wg.Wait()
}
