package message

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestFlowspecJSONProducerRoundTrip(t *testing.T) {
	views := []struct {
		name  string
		typ   bmp.PeerType
		flags byte
	}{
		{"in-pre", bmp.PeerType0, 0}, {"in-post", bmp.PeerType1, 0x40},
		{"out-pre", bmp.PeerType2, 0x10}, {"out-post", bmp.PeerType0, 0x50},
		{"loc", bmp.PeerType3, 0}, {"loc-filtered", bmp.PeerType3, 0x80},
	}
	for _, afi := range []uint16{1, 2} {
		for _, safi := range []uint8{133, 134} {
			for _, view := range views {
				for op := 0; op < 2; op++ {
					t.Run(fmt.Sprintf("%d/%d/%s/op%d", afi, safi, view.name, op), func(t *testing.T) {
						// RFC 8955 §4 / RFC 8956 §3: one prefix and one protocol component.
						components := []byte{1, 24, 192, 0, 2, 3, 0x81, 6}
						if afi == 2 {
							components = []byte{1, 32, 0, 0x20, 1, 0x0d, 0xb8, 3, 0x81, 6}
						}
						if safi == 134 {
							components = append([]byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 7}, components...)
						}
						wire := append([]byte{byte(afi >> 8), byte(afi), safi}, byte(len(components)))
						wire = append(wire, components...)
						var nlri bgp.MPNLRI
						var err error
						if op == 0 {
							// Empty next-hop is legal. Its representation is covered separately by
							// the next-hop fix; this test preserves whatever the producer publishes.
							wire = append([]byte{byte(afi >> 8), byte(afi), safi, 0, 0}, wire[3:]...)
							nlri, err = bgp.UnmarshalMPReachNLRI(wire, false, nil)
						} else {
							nlri, err = bgp.UnmarshalMPUnReachNLRI(wire, nil)
						}
						if err != nil {
							t.Fatal(err)
						}
						ph := makePeerHeader(t, view.typ, view.flags)
						p := NewProducer(&mockPublisher{}, false).(*producer)
						p.tableProperties[ph.GetTableKey()] = PerTableProperties{tableInfoTLVs: []bmp.InformationalTLV{{InformationType: 3, Information: []byte("vrf-blue")}}}
						msgs, err := p.flowspec(nlri, op, ph, minimalUpdate())
						if err != nil {
							t.Fatal(err)
						}
						if len(msgs) != 1 {
							t.Fatalf("records=%d", len(msgs))
						}
						want := msgs[0]
						if want.PeerIP == "" || want.SpecHash == "" || len(want.Spec) != 2 {
							t.Fatalf("incomplete producer record: %+v", want)
						}
						if view.typ == bmp.PeerType3 && want.TableName != "vrf-blue" {
							t.Fatalf("table name=%q", want.TableName)
						}
						data, err := json.Marshal(want)
						if err != nil {
							t.Fatal(err)
						}
						var got Flowspec
						if err = json.Unmarshal(data, &got); err != nil {
							t.Fatalf("decode producer JSON: %v; %s", err, data)
						}
						if !reflect.DeepEqual(&got, want) {
							t.Fatalf("roundtrip lost fields\ngot: %+v\nwant:%+v", &got, want)
						}
					})
				}
			}
		}
	}
}

func TestFlowspecJSONSchemaFields(t *testing.T) {
	// Fields added by storage consumers also follow the public schema.
	want := Flowspec{Key: "key", ID: "id", Rev: "rev", Action: "add", Sequence: 42, PathID: 17, SpecHash: "hash", OriginAS: 4200000001}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got Flowspec
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestFlowspecJSONValidation(t *testing.T) {
	tests := []struct {
		name, input string
		bad         bool
		specCount   int
	}{
		{"minimal", `{"action":"del","spec_hash":"hash"}`, false, 0},
		{"null required preserved", `{"action":null,"spec_hash":null}`, false, 0},
		{"empty required preserved", `{"action":"","spec_hash":""}`, false, 0},
		{"missing action", `{"spec_hash":"hash"}`, true, 0},
		{"missing hash", `{"action":"add"}`, true, 0},
		{"wrong action", `{"action":7,"spec_hash":"hash"}`, true, 0},
		{"wrong hash", `{"action":"add","spec_hash":7}`, true, 0},
		{"peer type", `{"action":"add","spec_hash":"h","peer_type":"bad"}`, true, 0},
		{"peer ip", `{"action":"add","spec_hash":"h","peer_ip":7}`, true, 0},
		{"rib flag", `{"action":"add","spec_hash":"h","is_loc_rib":7}`, true, 0},
		{"optional nexthop type", `{"action":"add","spec_hash":"h","nexthop":7}`, true, 0},
		{"spec object", `{"action":"add","spec_hash":"h","spec":{}}`, true, 0},
		{"spec no type", `{"action":"add","spec_hash":"h","spec":[{}]}`, true, 0},
		{"spec string type", `{"action":"add","spec_hash":"h","spec":[{"type":"1"}]}`, true, 0},
		{"spec fraction", `{"action":"add","spec_hash":"h","spec":[{"type":1.5}]}`, true, 0},
		{"spec range", `{"action":"add","spec_hash":"h","spec":[{"type":256}]}`, true, 0},
		{"bad prefix", `{"action":"add","spec_hash":"h","spec":[{"type":1,"prefix":"!"}]}`, true, 0},
		{"bad generic", `{"action":"add","spec_hash":"h","spec":[{"type":3,"op_val_pairs":"bad"}]}`, true, 0},
		{"unknown skipped", `{"action":"add","spec_hash":"h","spec":[{"type":255},{"type":1,"prefix_len":0}]}`, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := Flowspec{Action: "unchanged", SpecHash: "unchanged"}
			got := before
			err := json.Unmarshal([]byte(tt.input), &got)
			if (err != nil) != tt.bad {
				t.Fatalf("error=%v, want error=%v", err, tt.bad)
			}
			if tt.bad && !reflect.DeepEqual(got, before) {
				t.Fatalf("error mutated receiver: %+v", got)
			}
			if !tt.bad && len(got.Spec) != tt.specCount {
				t.Fatalf("spec count=%d", len(got.Spec))
			}
		})
	}
}
