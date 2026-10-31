package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

func peDistWire(flags byte, value []byte) []byte {
	return append([]byte{flags, 27, byte(len(value))}, value...)
}

// peDistReach is an MP_REACH_NLRI (AFI 1, SAFI 5) with the given routes.
func peDistReach(routes ...[]byte) []byte {
	v := []byte{0, 1, 5, 4, 192, 0, 2, 254, 0}
	for _, r := range routes {
		v = append(v, r...)
	}
	return append([]byte{0x80, 14, byte(len(v))}, v...)
}

// peDistType1 is an Intra-AS I-PMSI A-D route with a zero RD.
func peDistType1(orig []byte) []byte {
	return append(append([]byte{1, byte(8 + len(orig))}, make([]byte, 8)...), orig...)
}

func TestPEDistinguisherLabelsTreatAsWithdraw(t *testing.T) {
	v4 := []byte{192, 0, 2, 1, 0, 1, 0}
	v6o := make([]byte, 16)
	v6o[0], v6o[1], v6o[15] = 0x20, 0x01, 0x99
	r4 := peDistType1([]byte{192, 0, 2, 1})
	r6 := peDistType1(v6o)
	legacyNLRI := []byte{24, 203, 0, 113}
	legacyWithdrawn := []byte{24, 198, 51, 100}
	// MP_REACH for IPv4 unicast, 192.0.2.0/24.
	unicastReach := []byte{0x80, 14, 13, 0, 1, 1, 4, 10, 0, 0, 1, 0, 24, 192, 0, 2}
	bad := peDistWire(0xe0, make([]byte, 8))
	badNoPartial := peDistWire(0xc0, make([]byte, 8))
	good := peDistWire(0xc0, v4)

	tests := []struct {
		name      string
		withdrawn []byte
		attrs     []byte
		nlri      []byte
		// want maps message type to the ordered actions published.
		want map[int][]string
	}{
		{"mcast-vpn valid", nil, append(peDistReach(r4), good...), nil, map[int][]string{bmp.MCASTVPNV4Msg: {"add"}}},
		{"mcast-vpn malformed partial", nil, append(peDistReach(r4), bad...), nil, map[int][]string{bmp.MCASTVPNV4Msg: {"del"}}},
		{"mcast-vpn malformed no partial", nil, append(peDistReach(r4), badNoPartial...), nil, map[int][]string{bmp.MCASTVPNV4Msg: {"add"}}},
		{"mcast-vpn empty attr partial", nil, append(peDistReach(r4), peDistWire(0xe0, nil)...), nil, map[int][]string{bmp.MCASTVPNV4Msg: {"add"}}},
		{"mcast-vpn mixed originators partial, attr before reach", nil, append(peDistWire(0xe0, v4), peDistReach(r4, r6)...), nil, map[int][]string{bmp.MCASTVPNV4Msg: {"del", "del"}}},
		{"mcast-vpn mixed originators partial, reach before attr", nil, append(peDistReach(r4, r6), peDistWire(0xe0, v4)...), nil, map[int][]string{bmp.MCASTVPNV4Msg: {"del", "del"}}},
		{"mcast-vpn mixed originators no partial", nil, append(peDistReach(r4, r6), peDistWire(0xc0, v4)...), nil, map[int][]string{bmp.MCASTVPNV4Msg: {"add", "add"}}},
		{"other family in same update", nil, append(append(peDistReach(r4), unicastReach...), bad...), nil,
			map[int][]string{bmp.MCASTVPNV4Msg: {"del"}, bmp.UnicastPrefixV4Msg: {"del"}}},
		{"legacy nlri malformed partial", nil, bad, legacyNLRI, map[int][]string{bmp.UnicastPrefixV4Msg: {"del"}}},
		{"legacy nlri malformed no partial", nil, badNoPartial, legacyNLRI, map[int][]string{bmp.UnicastPrefixV4Msg: {"add"}}},
		{"legacy nlri ambiguous 133 not unicast either way partial", nil, peDistWire(0xe0, make([]byte, 133)), legacyNLRI, map[int][]string{bmp.UnicastPrefixV4Msg: {"del"}}},
		{"legacy withdrawn and nlri malformed partial", legacyWithdrawn, bad, legacyNLRI, map[int][]string{bmp.UnicastPrefixV4Msg: {"del", "del"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingPublisher{}
			p := NewProducer(rec, true).(*producer)
			p.produceRouteMonitorMessage(bmp.Message{
				PeerHeader: makePeerHeader(t, bmp.PeerType0, 0),
				Payload:    eorWire(t, tt.withdrawn, tt.attrs, tt.nlri),
			})
			got := map[int][]string{}
			for _, m := range rec.msgs {
				var v struct {
					Action string `json:"action"`
					IsEOR  bool   `json:"is_eor"`
				}
				if err := json.Unmarshal(m.payload, &v); err != nil {
					t.Fatal(err)
				}
				if v.IsEOR {
					t.Fatalf("unexpected End-of-RIB published (type %d)", m.msgType)
				}
				got[m.msgType] = append(got[m.msgType], v.Action)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("published %v, want %v", got, tt.want)
			}
			for typ, actions := range tt.want {
				if len(got[typ]) != len(actions) {
					t.Fatalf("type %d: published %v, want %v", typ, got[typ], actions)
				}
				for i := range actions {
					if got[typ][i] != actions[i] {
						t.Fatalf("type %d: published %v, want %v", typ, got[typ], actions)
					}
				}
			}
		})
	}
}
