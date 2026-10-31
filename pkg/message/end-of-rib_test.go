package message

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

func eorWire(t *testing.T, withdrawn, attrs, nlri []byte) *bmp.RouteMonitor {
	t.Helper()
	body := binary.BigEndian.AppendUint16(nil, uint16(len(withdrawn)))
	body = append(body, withdrawn...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(body, attrs...)
	body = append(body, nlri...)
	wire := bytes.Repeat([]byte{255}, 16)
	wire = binary.BigEndian.AppendUint16(wire, uint16(19+len(body)))
	wire = append(wire, 2)
	wire = append(wire, body...)
	rm, err := bmp.UnmarshalBMPRouteMonitorMessage(wire)
	if err != nil {
		t.Fatalf("wire parse: %v", err)
	}
	return rm
}

func eorUnreach(afi uint16, safi uint8) []byte {
	return []byte{0x80, 15, 3, byte(afi >> 8), byte(afi), safi}
}

func TestEndOfRIBWireFamilies(t *testing.T) {
	families := [][2]uint16{{1, 1}, {2, 1}, {1, 4}, {2, 4}, {1, 128}, {2, 128}, {25, 65}, {25, 70}, {1, 73}, {2, 73}, {1, 133}, {2, 133}, {1, 134}, {2, 134}, {1, 2}, {2, 2}, {1, 5}, {2, 5}, {1, 129}, {2, 129}, {1, 132}, {2, 132}, {1, 85}, {2, 85}, {16388, 71}, {16388, 72}, {16388, 80}, {0, 0}, {65535, 255}}
	for _, split := range []bool{false, true} {
		for _, family := range families {
			afi, safi := family[0], uint8(family[1])
			legacy := afi == 0
			if legacy {
				afi, safi = 1, 1
			}
			t.Run(fmt.Sprintf("%d/%d/legacy=%v/split=%v", afi, safi, legacy, split), func(t *testing.T) {
				rec := &recordingPublisher{}
				p := NewProducer(rec, split).(*producer)
				ph := makePeerHeader(t, bmp.PeerType0, 0)
				var attrs []byte
				if !legacy {
					attrs = eorUnreach(afi, safi)
				}
				p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: eorWire(t, nil, attrs, nil)})
				compat := legacy || (afi == 1 || afi == 2) && (safi == 1 || safi == 4 || safi == 128 || safi == 85) || afi == 25 && safi == 70
				want := 1
				if compat {
					want++
				}
				if len(rec.msgs) != want {
					t.Fatalf("published %d messages, want %d: %+v", len(rec.msgs), want, rec.msgs)
				}
				last := rec.msgs[len(rec.msgs)-1]
				if last.msgType != bmp.EndOfRIBMsg {
					t.Fatalf("last type=%d", last.msgType)
				}
				var marker EndOfRIB
				if err := json.Unmarshal(last.payload, &marker); err != nil {
					t.Fatal(err)
				}
				if marker.AFI != afi || marker.SAFI != safi || marker.PeerHash != ph.GetPeerHash() || marker.PeerRD != ph.GetPeerDistinguisherString() || marker.RouterHash != ph.Identity.RouterHash || marker.RouterIP != ph.Identity.RouterIP || marker.PeerIP != ph.GetPeerAddrString() || marker.PeerASN != ph.PeerAS || marker.RemoteBGPID != ph.GetPeerBGPIDString() || marker.Timestamp != ph.GetPeerTimestamp() {
					t.Fatalf("metadata: %+v", marker)
				}
				if compat {
					var old struct {
						IsEOR bool   `json:"is_eor"`
						AFI   uint16 `json:"afi"`
						SAFI  uint8  `json:"safi"`
					}
					if err := json.Unmarshal(rec.msgs[0].payload, &old); err != nil {
						t.Fatal(err)
					}
					if !old.IsEOR || old.AFI != afi || old.SAFI != safi {
						t.Fatalf("compatibility metadata: %+v", old)
					}
					topic := bmp.UnicastPrefixMsg
					switch {
					case afi == 25:
						topic = bmp.EVPNMsg
					case safi == 128:
						topic = bmp.L3VPNMsg
					case safi == 85:
						topic = bmp.MUPMsg
					}
					if split && afi != 25 {
						switch topic {
						case bmp.UnicastPrefixMsg:
							topic = bmp.UnicastPrefixV4Msg
							if afi == 2 {
								topic = bmp.UnicastPrefixV6Msg
							}
						case bmp.L3VPNMsg:
							topic = bmp.L3VPNV4Msg
							if afi == 2 {
								topic = bmp.L3VPNV6Msg
							}
						case bmp.MUPMsg:
							topic = bmp.MUPV4Msg
							if afi == 2 {
								topic = bmp.MUPV6Msg
							}
						}
					}
					if rec.msgs[0].msgType != topic {
						t.Fatalf("compat topic=%d want %d", rec.msgs[0].msgType, topic)
					}
				}
			})
		}
	}
}

func TestEndOfRIBRejectsOrdinaryUpdates(t *testing.T) {
	origin := []byte{0x40, 1, 1, 0}
	empty := eorUnreach(1, 1)
	reach := []byte{0x80, 14, 9, 0, 1, 1, 4, 10, 0, 0, 1, 0}
	route := []byte{24, 10, 1, 2}
	tests := []struct {
		name                   string
		withdrawn, attrs, nlri []byte
		wantRoutes             int
	}{
		{"pure withdrawal", route, nil, nil, 1},
		{"attribute only", nil, origin, nil, 0},
		{"empty reach", nil, reach, nil, 0},
		{"empty unreach with origin", nil, append(append([]byte{}, origin...), empty...), nil, 0},
		{"two empty unreach", nil, append(append([]byte{}, empty...), empty...), nil, 0},
		{"withdrawal with empty unreach", route, empty, nil, 1},
		{"add with empty unreach", nil, empty, route, 1},
		{"mixed MP", nil, append(append(append([]byte{0x80, 14, 13}, reach[3:]...), route...), empty...), nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingPublisher{}
			p := NewProducer(rec, false).(*producer)
			p.produceRouteMonitorMessage(bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, 0), Payload: eorWire(t, tt.withdrawn, tt.attrs, tt.nlri)})
			if len(rec.msgs) != tt.wantRoutes {
				t.Fatalf("route records=%d want %d", len(rec.msgs), tt.wantRoutes)
			}
			for _, m := range rec.msgs {
				var marker struct {
					IsEOR bool `json:"is_eor"`
				}
				if err := json.Unmarshal(m.payload, &marker); err != nil {
					t.Fatal(err)
				}
				if m.msgType == bmp.EndOfRIBMsg || marker.IsEOR {
					t.Fatalf("false EOR: %s", m.payload)
				}
			}
		})
	}
}

type eorFailPublisher struct {
	types []int
	keys  [][]byte
}

func (p *eorFailPublisher) PublishMessage(typ int, key, msg []byte) error {
	p.types = append(p.types, typ)
	p.keys = append(p.keys, append([]byte(nil), key...))
	return errors.New("publish failed")
}
func (p *eorFailPublisher) Stop() {}
func TestEndOfRIBPublisherFailure(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		rec := &eorFailPublisher{}
		p := NewProducer(rec, false).(*producer)
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		attrs := eorUnreach(1, 133)
		if legacy {
			attrs = nil
		}
		rm := eorWire(t, nil, attrs, nil)
		p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: rm})
		if len(rec.types) == 0 || rec.types[len(rec.types)-1] != bmp.EndOfRIBMsg {
			t.Fatalf("missing control publish attempt: %v", rec.types)
		}
		for _, key := range rec.keys {
			if string(key) != ph.Identity.RouterHash {
				t.Fatalf("key=%s", key)
			}
		}
		// Failure neither mutates the input nor suppresses the next received marker.
		before := len(rec.types)
		p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: rm})
		if len(rec.types) != 2*before {
			t.Fatalf("next marker suppressed: %v", rec.types)
		}
	}
}

func TestEndOfRIBRIBMetadata(t *testing.T) {
	tests := []struct {
		name                                string
		peerType                            bmp.PeerType
		flags                               byte
		inPost, outPost, out, loc, filtered bool
	}{
		{"in pre", bmp.PeerType0, 0, false, false, false, false, false},
		{"in post", bmp.PeerType0, 0x40, true, false, false, false, false},
		{"out pre", bmp.PeerType0, 0x10, false, false, true, false, false},
		{"out post", bmp.PeerType0, 0x50, false, true, true, false, false},
		{"loc", bmp.PeerType3, 0, false, false, false, true, false},
		{"loc filtered", bmp.PeerType3, 0x80, false, false, false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingPublisher{}
			p := NewProducer(rec, false).(*producer)
			ph := makePeerHeader(t, tt.peerType, tt.flags)
			p.tableProperties[ph.GetTableKey()] = PerTableProperties{tableInfoTLVs: []bmp.InformationalTLV{{InformationType: 3, Information: []byte("vrf-blue")}}}
			p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: eorWire(t, nil, eorUnreach(16388, 72), nil)})
			if len(rec.msgs) != 1 {
				t.Fatalf("records=%d", len(rec.msgs))
			}
			var marker EndOfRIB
			if err := json.Unmarshal(rec.msgs[0].payload, &marker); err != nil {
				t.Fatal(err)
			}
			table := ""
			if tt.loc {
				table = "vrf-blue"
			}
			if marker.PeerType != uint8(tt.peerType) || marker.IsAdjRIBInPost != tt.inPost || marker.IsAdjRIBOutPost != tt.outPost || marker.IsAdjRIBOut != tt.out || marker.IsLocRIB != tt.loc || marker.IsLocRIBFiltered != tt.filtered || marker.TableName != table {
				t.Fatalf("metadata: %+v", marker)
			}
		})
	}
}

func TestEndOfRIBFlowSpecMixedAttributeIsNotDelete(t *testing.T) {
	for _, afi := range []uint16{1, 2} {
		for _, safi := range []uint8{133, 134} {
			rec := &recordingPublisher{}
			p := NewProducer(rec, false).(*producer)
			attrs := append([]byte{0x40, 1, 1, 0}, eorUnreach(afi, safi)...)
			p.produceRouteMonitorMessage(bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, 0), Payload: eorWire(t, nil, attrs, nil)})
			if len(rec.msgs) != 0 {
				t.Fatalf("AFI=%d SAFI=%d published false route/control: %+v", afi, safi, rec.msgs)
			}
		}
	}
}

// Each producer has one table: this verifies baseline lookup compatibility,
// not isolation between distinguishers with the same formatted RD string.
func TestEndOfRIBLocRIBDistinguisherLookup(t *testing.T) {
	tests := []struct {
		name string
		pd   []byte
	}{
		{"opaque first", []byte{0, 3, 0, 0, 0, 0, 0, 1}},
		{"opaque second", []byte{0, 3, 0, 0, 0, 0, 0, 2}},
		{"RD type zero", []byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 1}},
		{"RD type two", []byte{0, 2, 0, 0, 0xfd, 0xe8, 0, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingPublisher{}
			p := NewProducer(rec, false).(*producer)
			ph := makePeerHeader(t, bmp.PeerType3, 0)
			ph.PeerDistinguisher = tt.pd
			p.tableProperties[ph.GetTableKey()] = PerTableProperties{tableInfoTLVs: []bmp.InformationalTLV{{InformationType: 3, Information: []byte(tt.name)}}}
			p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: eorWire(t, nil, eorUnreach(1, 133), nil)})
			if len(rec.msgs) != 1 || rec.msgs[0].msgType != bmp.EndOfRIBMsg {
				t.Fatalf("published=%+v", rec.msgs)
			}
			var marker EndOfRIB
			if err := json.Unmarshal(rec.msgs[0].payload, &marker); err != nil {
				t.Fatal(err)
			}
			if marker.TableName != tt.name || marker.PeerRD != ph.GetPeerDistinguisherString() {
				t.Fatalf("marker=%+v", marker)
			}
		})
	}
}

func TestEndOfRIBDistinctLocRIBTables(t *testing.T) {
	rec := &recordingPublisher{}
	p := NewProducer(rec, false).(*producer)
	first, second := makePeerHeader(t, bmp.PeerType3, 0), makePeerHeader(t, bmp.PeerType3, 0)
	second.PeerBGPID = []byte{10, 0, 0, 2}
	if first.GetTableKey() == second.GetTableKey() {
		t.Fatal("fixture table keys must differ")
	}
	for i, ph := range []*bmp.PerPeerHeader{first, second} {
		name := fmt.Sprintf("VRF-%d", i)
		p.tableProperties[ph.GetTableKey()] = PerTableProperties{tableInfoTLVs: []bmp.InformationalTLV{{InformationType: 3, Information: []byte(name)}}}
	}
	for i, ph := range []*bmp.PerPeerHeader{first, second} {
		rec.msgs = nil
		p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: eorWire(t, nil, eorUnreach(1, 133), nil)})
		if len(rec.msgs) != 1 {
			t.Fatalf("published=%+v", rec.msgs)
		}
		var marker EndOfRIB
		if err := json.Unmarshal(rec.msgs[0].payload, &marker); err != nil {
			t.Fatal(err)
		}
		if marker.TableName != fmt.Sprintf("VRF-%d", i) {
			t.Fatalf("wrong table: %+v", marker)
		}
	}
}
