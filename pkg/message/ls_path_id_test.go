package message

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/ls"
)

type lsPathFixture struct {
	name  string
	wire  []byte
	topic int
}

func lsPathFixtures() []lsPathFixture {
	node := testLSNodeNLRI80()
	prefix4 := append(bytes.Clone(node[4:]), messageInterASTLV(265, []byte{24, 192, 0, 2})...)
	prefix6 := append(bytes.Clone(node[4:]), messageInterASTLV(265, []byte{128, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})...)
	sidNode := append(messageInterASTLV(512, []byte{0, 0, 0xfd, 0xe8}), messageInterASTLV(515, []byte{0, 0, 0, 0, 0, 1})...)
	sid := append([]byte{byte(base.ISISL2), 0, 0, 0, 0, 0, 0, 0, 0}, messageInterASTLV(256, sidNode)...)
	sid = append(sid, messageInterASTLV(263, []byte{0, 0})...)
	sid = append(sid, messageInterASTLV(518, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})...)
	return []lsPathFixture{
		{"node", node, bmp.LSNodeMsg},
		{"link", testLSLinkNLRI80([]byte{1}), bmp.LSLinkMsg},
		{"IPv4 prefix", messageInterASTLV(3, prefix4), bmp.LSPrefixMsg},
		{"IPv6 prefix", messageInterASTLV(4, prefix6), bmp.LSPrefixMsg},
		{"SRv6 SID", messageInterASTLV(6, sid), bmp.LSSRv6SIDMsg},
		{"opaque", []byte{0, 99, 0, 3, 0xde, 0xad, 0xbe}, bmp.LSOpaqueMsg},
	}
}

func lsPathAttribute(typ byte, value []byte) []byte {
	header := []byte{0x80, typ}
	if len(value) > 255 {
		header[0] |= 0x10
		header = binary.BigEndian.AppendUint16(header, uint16(len(value)))
	} else {
		header = append(header, byte(len(value)))
	}
	return append(header, value...)
}

func lsPathPeerUp(t *testing.T, safi byte) *bmp.PeerUpMessage {
	t.Helper()
	open := func(as uint16, id byte) []byte {
		caps := []byte{1, 4, 0x40, 4, 0, safi, 69, 4, 0x40, 4, safi, 3, 65, 4, 0, 0, byte(as >> 8), byte(as)}
		body := []byte{4, byte(as >> 8), byte(as), 0, 90, 192, 0, 2, id, byte(2 + len(caps)), 2, byte(len(caps))}
		body = append(body, caps...)
		wire := binary.BigEndian.AppendUint16(bytes.Repeat([]byte{255}, 16), uint16(19+len(body)))
		return append(append(wire, 1), body...)
	}
	wire := make([]byte, 12)
	wire = append(wire, 192, 0, 2, 1, 0, 179, 0, 179)
	wire = append(wire, open(65000, 1)...)
	wire = append(wire, open(65001, 2)...)
	peer, err := bmp.UnmarshalPeerUpMessage(wire, false)
	if err != nil {
		t.Fatalf("parse PeerUp: %v", err)
	}
	return peer
}

func lsPathUpdate(t *testing.T, safi byte, withdrawn bool, payload []byte) *bmp.RouteMonitor {
	t.Helper()
	if withdrawn {
		return eorWire(t, nil, lsPathAttribute(15, append([]byte{0x40, 4, safi}, payload...)), nil)
	}
	// ORIGIN and AS_PATH accompany the MP_REACH, which supplies the next hop.
	attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe8}
	attrs = append(attrs, lsPathAttribute(14, append([]byte{0x40, 4, safi, 4, 192, 0, 2, 9, 0}, payload...))...)
	if safi == 80 {
		attribute := testLSUpdate(testLSSequence(),
			lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{0, 0, 0, 10}},
			lsSPFTLV{typeID: bgpLSPrefixMetricTLV, value: []byte{0, 0, 0, 10}})
		attrs = append(attrs, lsPathAttribute(29, attribute.PathAttributes[0].Attribute)...)
	}
	return eorWire(t, nil, attrs, nil)
}

func lsPathJSON(t *testing.T, topic int, data []byte) map[string]json.RawMessage {
	t.Helper()
	var target any
	switch topic {
	case bmp.LSNodeMsg:
		target = &LSNode{}
	case bmp.LSLinkMsg:
		target = &LSLink{}
	case bmp.LSPrefixMsg:
		target = &LSPrefix{}
	case bmp.LSSRv6SIDMsg:
		target = &LSSRv6SID{}
	case bmp.LSOpaqueMsg:
		target = &LSOpaque{}
	default:
		t.Fatalf("unexpected topic %d", topic)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("typed JSON decode: %v", err)
	}
	roundTrip, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	var original, decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(roundTrip, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Errorf("typed JSON round trip changed message: before=%s after=%s", data, roundTrip)
	}
	return original
}

// RFC 7911 §§2,5: withdrawing one path must leave another path for the same NLRI.
func TestLSPathIDNegotiatedWire(t *testing.T) {
	for _, safi := range []byte{71, 80} {
		for _, fixture := range lsPathFixtures() {
			t.Run(fmt.Sprintf("SAFI%d/%s", safi, fixture.name), func(t *testing.T) {
				rec := &recordingPublisher{}
				p := NewProducer(rec, false).(*producer)
				ph := makePeerHeader(t, bmp.PeerType0, 0)
				ph.PeerAS, ph.PeerBGPID = 65001, []byte{192, 0, 2, 2}
				p.producingWorker(bmp.Message{PeerHeader: ph, Payload: lsPathPeerUp(t, safi)})
				if !p.GetAddPathCapability(ph.GetTableKey())[bgp.NLRIMessageType(16388, safi)] {
					t.Fatal("ADD-PATH was not negotiated through PeerUp")
				}
				rec.msgs = nil
				first := append([]byte{0, 0, 0, 7}, fixture.wire...)
				second := append([]byte{0, 0, 0, 9}, fixture.wire...)
				p.producingWorker(bmp.Message{PeerHeader: ph, Payload: lsPathUpdate(t, safi, false, append(bytes.Clone(first), second...))})
				p.producingWorker(bmp.Message{PeerHeader: ph, Payload: lsPathUpdate(t, safi, true, first)})
				if len(rec.msgs) != 3 {
					t.Fatalf("published %d messages, want two adds and one del", len(rec.msgs))
				}
				paths := map[uint32]bool{}
				var initial map[string]json.RawMessage
				for i, want := range []struct {
					pathID uint32
					action string
				}{{7, "add"}, {9, "add"}, {7, "del"}} {
					msg := rec.msgs[i]
					if msg.msgType != fixture.topic {
						t.Fatalf("topic = %d, want %d", msg.msgType, fixture.topic)
					}
					decoded := lsPathJSON(t, msg.msgType, msg.payload)
					var pathID uint32
					var action string
					if err := json.Unmarshal(decoded["path_id"], &pathID); err != nil {
						t.Fatalf("missing/invalid path_id: %s (%v)", msg.payload, err)
					}
					if err := json.Unmarshal(decoded["action"], &action); err != nil {
						t.Fatal(err)
					}
					if pathID != want.pathID || action != want.action {
						t.Errorf("publication %d = %s PathID %d, want %s %d", i, action, pathID, want.action, want.pathID)
					}
					if action == "del" {
						delete(paths, pathID)
					} else {
						paths[pathID] = true
					}
					if i == 0 {
						initial = decoded
					}
					for _, key := range []string{"hash", "router_hash", "peer_hash", "local_node_hash", "remote_node_hash"} {
						if !bytes.Equal(initial[key], decoded[key]) {
							t.Errorf("structural %s changed between paths/withdrawal: %s != %s", key, initial[key], decoded[key])
						}
					}
				}
				if len(paths) != 1 || !paths[9] {
					t.Errorf("replayed paths = %v, want only PathID 9", paths)
				}
			})
		}
	}
}

func TestLSPathIDJSONBounds(t *testing.T) {
	for _, topic := range []int{bmp.LSNodeMsg, bmp.LSPrefixMsg, bmp.LSSRv6SIDMsg, bmp.LSOpaqueMsg} {
		for _, id := range []uint32{0, 1, ^uint32(0)} {
			t.Run(fmt.Sprintf("topic%d/id%d", topic, id), func(t *testing.T) {
				// Start with real publication JSON to retain all required schema fields.
				fixture := lsPathFixtures()[0]
				for _, candidate := range lsPathFixtures() {
					if candidate.topic == topic {
						fixture = candidate
						break
					}
				}
				rec := &recordingPublisher{}
				p := &producer{publisher: rec}
				wire := binary.BigEndian.AppendUint32(nil, id)
				wire = append(wire, fixture.wire...)
				nlri, err := bgp.UnmarshalMPReachNLRI(append([]byte{0x40, 4, 71, 4, 192, 0, 2, 9, 0}, wire...), false, map[int]bool{71: true})
				if err != nil {
					t.Fatal(err)
				}
				p.processMPUpdate(nlri, AddPrefix, minimalPeerHeader(), minimalUpdate())
				if len(rec.msgs) != 1 {
					t.Fatalf("published %d messages, want one", len(rec.msgs))
				}
				decoded := lsPathJSON(t, topic, rec.msgs[0].payload)
				raw, present := decoded["path_id"]
				if id == 0 {
					if present {
						t.Errorf("zero path_id should be omitted: %s", rec.msgs[0].payload)
					}
				} else if string(raw) != fmt.Sprint(id) {
					t.Errorf("path_id = %s, want exact uint32 %d", raw, id)
				}
			})
		}
	}
}

func TestLSPathIDSAFI72Mapping(t *testing.T) {
	// SAFI72's separate framing defect is outside this change. These are
	// decoded-object mapping checks, not claims about its wire compliance.
	rd, err := base.MakeRD([]byte{0, 0, 0, 100, 0, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range lsPathFixtures() {
		for _, operation := range []int{AddPrefix, DelPrefix} {
			t.Run(fmt.Sprintf("%s/op%d", fixture.name, operation), func(t *testing.T) {
				decoded, err := ls.UnmarshalLSNLRI71(fixture.wire, false)
				if err != nil {
					t.Fatal(err)
				}
				element := decoded.NLRI[0]
				mock := &safi72MockNLRI{nlri72: &ls.NLRI72{NLRI: []ls.VPNElement{{
					RD: rd, Type: element.Type, Length: element.Length, LS: element.LS, PathID: 0xffffffff,
				}}}}
				rec := &recordingPublisher{}
				p := &producer{publisher: rec}
				p.processNLRI72SubTypes(mock, operation, minimalPeerHeader(), minimalUpdate())
				if len(rec.msgs) != 1 || rec.msgs[0].msgType != fixture.topic {
					t.Fatalf("published = %+v, want one topic %d", rec.msgs, fixture.topic)
				}
				body := lsPathJSON(t, fixture.topic, rec.msgs[0].payload)
				if string(body["path_id"]) != "4294967295" || string(body["route_distinguisher"]) != `"100:1"` {
					t.Errorf("lost PathID or RD: %s", rec.msgs[0].payload)
				}
			})
		}
	}
}

func TestLSPathIDSPFTreatAsWithdraw(t *testing.T) {
	for _, malformedAttribute := range []bool{false, true} {
		t.Run(fmt.Sprintf("wholeBatch=%t", malformedAttribute), func(t *testing.T) {
			validNode := append([]byte{0, 0, 0, 7}, testLSNodeNLRI80()...)
			invalidNode := testLSNodeNLRI80()
			invalidNode[4] = byte(base.OSPFv2)
			invalidNode = append([]byte{0, 0, 0, 9}, invalidNode...)
			nlri, err := bgp.UnmarshalMPReachNLRI(append([]byte{0x40, 4, 80, 4, 192, 0, 2, 9, 0}, append(validNode, invalidNode...)...), false, map[int]bool{80: true})
			if err != nil {
				t.Fatal(err)
			}
			update := testLSUpdate(testLSSequence())
			if malformedAttribute {
				update = testLSUpdate(lsSPFTLV{typeID: bgpLSSPFSequenceNumberTLV, value: []byte{1}})
			}
			rec := &recordingPublisher{}
			p := &producer{publisher: rec}
			p.processMPUpdate(nlri, AddPrefix, minimalPeerHeader(), update)
			if len(rec.msgs) != 2 {
				t.Fatalf("published %d messages, want two", len(rec.msgs))
			}
			got := map[string]string{}
			for _, msg := range rec.msgs {
				body := lsPathJSON(t, msg.msgType, msg.payload)
				got[string(body["path_id"])] = string(body["action"])
			}
			want := map[string]string{"7": `"add"`, "9": `"del"`}
			if malformedAttribute {
				want["7"] = `"del"`
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("SPF paths = %v, want %v", got, want)
			}
		})
	}
}
