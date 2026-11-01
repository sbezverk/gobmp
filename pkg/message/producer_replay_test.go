package message

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func replayRouteWire(t *testing.T, family bgp.AFISAFI, kind string, addPath bool) *bmp.RouteMonitor {
	t.Helper()
	nlri := []byte{24, 192, 0, 2}
	nextHop := []byte{192, 0, 2, 1}
	if family.AFI == 2 {
		nlri = []byte{32, 0x20, 1, 0x0d, 0xb8}
		nextHop = []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	}
	if addPath {
		nlri = append([]byte{0, 0, 1, 0}, nlri...)
	}
	attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 0, 0x40, 3, 4, 192, 0, 2, 1}
	switch kind {
	case "legacy-add":
		return eorWire(t, nil, attrs, nlri)
	case "legacy-del":
		return eorWire(t, nlri, nil, nil)
	case "mp-add":
		return eorWire(t, nil, append(attrs, dPathReach(family.AFI, family.SAFI, nextHop, nlri)...), nil)
	case "mp-del":
		return eorWire(t, nil, dPathUnreach(family.AFI, family.SAFI, nlri), nil)
	default:
		t.Fatalf("unknown replay fixture kind %q", kind)
		return nil
	}
}

func replayedRoutes(t *testing.T, rec *recordingPublisher) []UnicastPrefix {
	t.Helper()
	var routes []UnicastPrefix
	for _, msg := range rec.msgs {
		if msg.msgType != bmp.UnicastPrefixMsg {
			continue
		}
		var route UnicastPrefix
		if err := json.Unmarshal(msg.payload, &route); err != nil {
			t.Fatal(err)
		}
		routes = append(routes, route)
	}
	return routes
}

func checkReplayedRoute(t *testing.T, route UnicastPrefix, up bmp.Message, family bgp.AFISAFI, kind string, addPath bool) {
	t.Helper()
	wantPrefix, wantLength, wantPath, wantAction := "192.0.2.0", int32(24), int32(0), "add"
	if family.AFI == 2 {
		wantPrefix, wantLength = "2001:db8::", 32
	}
	if addPath {
		wantPath = 256
	}
	if kind == "legacy-del" || kind == "mp-del" {
		wantAction = "del"
	}
	if route.Prefix != wantPrefix || route.PrefixLen != wantLength || route.PathID != wantPath || route.Action != wantAction || route.IsEOR {
		t.Fatalf("route = %+v, want %s %s/%d PathID%d", route, wantAction, wantPrefix, wantLength, wantPath)
	}
	identity := bmp.IdentityFromPeerUp(up)
	ph := up.PeerHeader
	if route.RouterIP != identity.RouterIP || route.RouterHash != identity.RouterHash || route.PeerIP != ph.GetPeerAddrString() || route.PeerHash != ph.GetPeerHash() || route.RemoteBGPID != ph.GetPeerBGPIDString() || route.PeerASN != ph.PeerAS {
		t.Fatalf("route identity = %+v, want own PeerUp identity %+v", route, identity)
	}
	if ph.PeerType == bmp.PeerType3 && (!route.IsLocRIB || route.TableName != "VRF-A") {
		t.Fatalf("Loc-RIB route metadata = %+v, want VRF-A", route)
	}
}

func TestProducerPrePeerUpReplayOwnPeerState(t *testing.T) {
	family := bgp.AFISAFI{AFI: 1, SAFI: 1}
	views := []struct {
		name          string
		flags         byte
		local, remote uint8
	}{
		{"in", 0, 1, 2},
		{"out", 0x10, 2, 1},
	}
	for _, view := range views {
		for _, ownPeer := range []bool{true, false} {
			for _, addPath := range []bool{true, false} {
				for _, kind := range []string{"legacy-add", "legacy-del", "mp-add", "mp-del"} {
					t.Run(fmt.Sprintf("%s/own=%v/addpath=%v/%s", view.name, ownPeer, addPath, kind), func(t *testing.T) {
						rec := &recordingPublisher{}
						p := NewProducer(rec, false).(*producer)
						ph := makePeerHeader(t, bmp.PeerType0, 0)
						ph.PeerAddress[15] = 2
						routePH := *ph
						if view.flags != 0 {
							routePH = *makePeerHeader(t, bmp.PeerType0, view.flags)
							routePH.PeerAddress[15] = 2
						}
						upPayload := buildPeerUpMessage(t, "198.51.100.1")
						upPayload.SentOpen, upPayload.ReceivedOpen = addPathOpen(t, nil, nil), addPathOpen(t, nil, nil)
						if addPath {
							upPayload.SentOpen = addPathOpen(t, []bgp.AFISAFI{family}, map[bgp.AFISAFI]uint8{family: view.local})
							upPayload.ReceivedOpen = addPathOpen(t, []bgp.AFISAFI{family}, map[bgp.AFISAFI]uint8{family: view.remote})
						}
						up := bmp.Message{PeerHeader: ph, SpeakerIP: "203.0.113.9", Payload: upPayload}
						early := bmp.Message{PeerHeader: &routePH, SpeakerIP: up.SpeakerIP, Payload: replayRouteWire(t, family, kind, addPath)}
						p.producingWorker(early)
						firstUp := up
						if !ownPeer {
							other := makePeerHeader(t, bmp.PeerType0, 0)
							other.PeerAddress[15] = 1
							firstUp = bmp.Message{PeerHeader: other, SpeakerIP: up.SpeakerIP, Payload: buildPeerUpMessage(t, "198.51.100.9")}
						}
						p.producingWorker(firstUp)
						wantRoutes := 0
						if ownPeer {
							wantRoutes = 1
						}
						if routes := replayedRoutes(t, rec); len(routes) != wantRoutes || len(rec.msgs) != 1+wantRoutes || rec.msgs[0].msgType != bmp.PeerStateChangeMsg {
							t.Fatalf("after first PeerUp: routes=%+v publications=%d, want %d route(s)", routes, len(rec.msgs), wantRoutes)
						}
						if !ownPeer {
							p.producingWorker(up)
							if routes := replayedRoutes(t, rec); len(routes) != 0 || len(rec.msgs) != 2 {
								t.Fatalf("later own PeerUp resurrected discarded route: %+v", routes)
							}
						}
						p.producingWorker(early)
						routes := replayedRoutes(t, rec)
						if len(routes) != wantRoutes+1 {
							t.Fatalf("route count = %d, want %d", len(routes), wantRoutes+1)
						}
						for _, route := range routes {
							checkReplayedRoute(t, route, up, family, kind, addPath)
							if route.IsAdjRIBOut != (view.flags != 0) {
								t.Fatalf("wrong route direction: %+v", route)
							}
						}
						if len(p.prePeerUp) != 0 || p.prePeerUpBytes != 0 {
							t.Fatal("replay retained buffered data")
						}
					})
				}
			}
		}
	}
}

func TestProducerPrePeerUpReplayLocRIBFamilies(t *testing.T) {
	v4, v6 := bgp.AFISAFI{AFI: 1, SAFI: 1}, bgp.AFISAFI{AFI: 2, SAFI: 1}
	cases := []struct {
		name       string
		family     bgp.AFISAFI
		declared   bgp.AFISAFI
		kind       string
		addPath    bool
		wantReplay bool
	}{
		{"legacy add unknown", v4, v6, "legacy-add", true, false},
		{"legacy del unknown", v4, v6, "legacy-del", true, false},
		{"MP add unknown", v6, v4, "mp-add", true, false},
		{"MP del unknown", v6, v4, "mp-del", true, false},
		{"same AFI different SAFI", v6, bgp.AFISAFI{AFI: 2, SAFI: 4}, "mp-add", true, false},
		{"same SAFI different AFI", v6, v4, "mp-del", false, false},
		{"legacy add declared ADD-PATH", v4, v4, "legacy-add", true, true},
		{"legacy del declared ADD-PATH", v4, v4, "legacy-del", true, true},
		{"MP add declared ADD-PATH", v6, v6, "mp-add", true, true},
		{"MP del declared ADD-PATH", v6, v6, "mp-del", true, true},
		{"legacy add declared plain", v4, v4, "legacy-add", false, true},
		{"legacy del declared plain", v4, v4, "legacy-del", false, true},
		{"MP add declared plain", v6, v6, "mp-add", false, true},
		{"MP del declared plain", v6, v6, "mp-del", false, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingPublisher{}
			p := NewProducer(rec, false).(*producer)
			ph := makePeerHeader(t, bmp.PeerType3, 0)
			upPayload := buildPeerUpMessage(t, "0.0.0.0")
			modes := map[bgp.AFISAFI]uint8(nil)
			if tt.addPath {
				modes = map[bgp.AFISAFI]uint8{tt.declared: 1}
			}
			upPayload.SentOpen = addPathOpen(t, []bgp.AFISAFI{tt.declared}, modes)
			upPayload.ReceivedOpen = upPayload.SentOpen
			upPayload.Information = []bmp.InformationalTLV{{InformationType: 3, Information: []byte("VRF-A")}}
			up := bmp.Message{PeerHeader: ph, SpeakerIP: "203.0.113.9", Payload: upPayload}
			early := bmp.Message{PeerHeader: ph, SpeakerIP: up.SpeakerIP, Payload: replayRouteWire(t, tt.family, tt.kind, tt.addPath)}
			p.producingWorker(early)
			p.producingWorker(up)
			want := 0
			if tt.wantReplay {
				want = 1
			}
			routes := replayedRoutes(t, rec)
			if len(routes) != want || len(rec.msgs) != want+1 {
				t.Fatalf("routes=%+v publications=%d, want %d route(s)", routes, len(rec.msgs), want)
			}
			for _, route := range routes {
				checkReplayedRoute(t, route, up, tt.family, tt.kind, tt.addPath)
			}
			if !tt.wantReplay {
				upPayload = buildPeerUpMessage(t, "0.0.0.0")
				upPayload.SentOpen = addPathOpen(t, []bgp.AFISAFI{tt.family}, nil)
				if tt.addPath {
					upPayload.SentOpen = addPathOpen(t, []bgp.AFISAFI{tt.family}, map[bgp.AFISAFI]uint8{tt.family: 1})
				}
				upPayload.ReceivedOpen = upPayload.SentOpen
				upPayload.Information = []bmp.InformationalTLV{{InformationType: 3, Information: []byte("VRF-A")}}
				up.Payload = upPayload
				p.producingWorker(up)
				if routes := replayedRoutes(t, rec); len(routes) != 0 || len(rec.msgs) != 2 {
					t.Fatalf("later family PeerUp resurrected discarded route: %+v", routes)
				}
				p.producingWorker(early)
				routes = replayedRoutes(t, rec)
				if len(routes) != 1 {
					t.Fatalf("live known-family route count = %d, want 1", len(routes))
				}
				checkReplayedRoute(t, routes[0], up, tt.family, tt.kind, tt.addPath)
			}
		})
	}
}

func TestProducerPrePeerUpReplayLocRIBWholeUpdate(t *testing.T) {
	v4 := bgp.AFISAFI{AFI: 1, SAFI: 1}
	v4NLRI, v6NLRI := []byte{24, 192, 0, 2}, []byte{32, 0x20, 1, 0x0d, 0xb8}
	v4Reach := dPathReach(1, 1, []byte{192, 0, 2, 1}, v4NLRI)
	v6Reach := dPathReach(2, 1, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, v6NLRI)
	cases := []struct {
		name      string
		declared  []bgp.AFISAFI
		withdrawn []byte
		attrs     []byte
		nlri      []byte
		want      int
	}{
		{"known reach before unknown unreach", []bgp.AFISAFI{v4}, nil, append(v4Reach, dPathUnreach(2, 1, v6NLRI)...), nil, 0},
		{"unknown reach before known unreach", []bgp.AFISAFI{v4}, nil, append(v6Reach, dPathUnreach(1, 1, v4NLRI)...), nil, 0},
		{"known reach with unknown legacy", []bgp.AFISAFI{{AFI: 2, SAFI: 1}}, nil, v6Reach, v4NLRI, 0},
		{"known reach with unknown legacy withdrawal", []bgp.AFISAFI{{AFI: 2, SAFI: 1}}, v4NLRI, v6Reach, nil, 0},
		{"truncated MP family before known legacy", []bgp.AFISAFI{v4}, nil, []byte{0x80, 14, 2, 0, 1}, v4NLRI, 0},
		{"truncated MP unreach before known reach", []bgp.AFISAFI{v4}, nil, append(v4Reach, []byte{0x80, 15, 2, 0, 1}...), nil, 0},
		{"known reach and unreach", []bgp.AFISAFI{v4, {AFI: 2, SAFI: 1}}, nil, append(v4Reach, dPathUnreach(2, 1, v6NLRI)...), nil, 2},
		{"known MP and legacy", []bgp.AFISAFI{v4, {AFI: 2, SAFI: 1}}, nil, v6Reach, v4NLRI, 2},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingPublisher{}
			p := NewProducer(rec, false).(*producer)
			ph := makePeerHeader(t, bmp.PeerType3, 0)
			up := buildPeerUpMessage(t, "0.0.0.0")
			up.SentOpen = addPathOpen(t, tt.declared, nil)
			up.ReceivedOpen = up.SentOpen
			p.producingWorker(bmp.Message{PeerHeader: ph, Payload: eorWire(t, tt.withdrawn, tt.attrs, tt.nlri)})
			p.producingWorker(bmp.Message{PeerHeader: ph, SpeakerIP: "203.0.113.9", Payload: up})
			if len(rec.msgs) != tt.want+1 || rec.msgs[0].msgType != bmp.PeerStateChangeMsg || len(replayedRoutes(t, rec)) != tt.want {
				t.Fatalf("UPDATE publications = %d, want PeerUp and %d routes", len(rec.msgs), tt.want)
			}
		})
	}
}

func TestProducerPrePeerUpReplayLocRIBEOR(t *testing.T) {
	v4, v6 := bgp.AFISAFI{AFI: 1, SAFI: 1}, bgp.AFISAFI{AFI: 2, SAFI: 1}
	for _, legacy := range []bool{false, true} {
		for _, known := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%v/known=%v", legacy, known), func(t *testing.T) {
				rec := &recordingPublisher{}
				p := NewProducer(rec, false).(*producer)
				ph := makePeerHeader(t, bmp.PeerType3, 0)
				family, attrs := v6, eorUnreach(2, 1)
				if legacy {
					family, attrs = v4, nil
				}
				declared := family
				if !known {
					declared = bgp.AFISAFI{AFI: 25, SAFI: 70}
				}
				up := buildPeerUpMessage(t, "0.0.0.0")
				up.SentOpen = addPathOpen(t, []bgp.AFISAFI{declared}, nil)
				up.ReceivedOpen = up.SentOpen
				up.Information = []bmp.InformationalTLV{{InformationType: 3, Information: []byte("VRF-A")}}
				p.producingWorker(bmp.Message{PeerHeader: ph, Payload: eorWire(t, nil, attrs, nil)})
				p.producingWorker(bmp.Message{PeerHeader: ph, SpeakerIP: "203.0.113.9", Payload: up})
				want := 1
				if known {
					want = 3
				}
				if len(rec.msgs) != want {
					t.Fatalf("EOR publications=%d, want %d", len(rec.msgs), want)
				}
				if known {
					var marker EndOfRIB
					if rec.msgs[2].msgType != bmp.EndOfRIBMsg {
						t.Fatalf("last publication = %d, want EOR control", rec.msgs[2].msgType)
					}
					if err := json.Unmarshal(rec.msgs[2].payload, &marker); err != nil {
						t.Fatal(err)
					}
					if marker.AFI != family.AFI || marker.SAFI != family.SAFI || marker.TableName != "VRF-A" || marker.RouterIP != "203.0.113.9" || !marker.IsLocRIB {
						t.Fatalf("wrong EOR metadata: %+v", marker)
					}
				}
			})
		}
	}
}

func TestProducerPrePeerUpReplayStatisticsAndOrder(t *testing.T) {
	for _, peerType := range []bmp.PeerType{bmp.PeerType0, bmp.PeerType3} {
		t.Run(fmt.Sprintf("peer%d", peerType), func(t *testing.T) {
			rec := &recordingPublisher{}
			p := NewProducer(rec, false).(*producer)
			own := makePeerHeader(t, peerType, 0)
			other := makePeerHeader(t, peerType, 0)
			if peerType == bmp.PeerType3 {
				other.PeerDistinguisher[7] = 1
			} else {
				copy(own.PeerAddress[12:], []byte{192, 0, 2, 1})
				copy(other.PeerAddress[12:], []byte{192, 0, 2, 2})
			}
			upPayload := buildPeerUpMessage(t, "198.51.100.1")
			if peerType == bmp.PeerType3 {
				upPayload = buildPeerUpMessage(t, "0.0.0.0")
				upPayload.SentOpen = addPathOpen(t, []bgp.AFISAFI{{AFI: 2, SAFI: 1}}, nil)
				upPayload.ReceivedOpen = upPayload.SentOpen
			}
			up := bmp.Message{PeerHeader: own, SpeakerIP: "203.0.113.9", Payload: upPayload}
			for i, ph := range []*bmp.PerPeerHeader{own, other, own} {
				stats, err := bmp.UnmarshalBMPStatsReportMessage([]byte{0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, byte(41 + i)})
				if err != nil {
					t.Fatal(err)
				}
				p.producingWorker(bmp.Message{PeerHeader: ph, SpeakerIP: up.SpeakerIP, Payload: stats})
			}
			p.producingWorker(up)
			if len(rec.msgs) != 3 || rec.msgs[0].msgType != bmp.PeerStateChangeMsg {
				t.Fatalf("publications = %d, want PeerUp and two own statistics", len(rec.msgs))
			}
			identity := bmp.IdentityFromPeerUp(up)
			for i, count := range []uint32{41, 43} {
				msg := rec.msgs[i+1]
				var stats Stats
				if msg.msgType != bmp.StatsReportMsg {
					t.Fatalf("publication type = %d, want statistics", msg.msgType)
				}
				if err := json.Unmarshal(msg.payload, &stats); err != nil {
					t.Fatal(err)
				}
				if stats.PrefixesRejectedInbound != count || stats.RouterIP != identity.RouterIP || stats.RouterHash != identity.RouterHash || stats.RemoteIP != own.GetPeerAddrString() || stats.RemoteBGPID != own.GetPeerBGPIDString() || stats.PeerRD != own.GetPeerDistinguisherString() || stats.RemoteASN != own.PeerAS {
					t.Fatalf("wrong ordered statistics or identity: %+v", stats)
				}
			}
			if len(p.prePeerUp) != 0 || p.prePeerUpBytes != 0 {
				t.Fatal("replay retained buffered statistics")
			}
		})
	}
}
