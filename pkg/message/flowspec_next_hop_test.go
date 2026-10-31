package message

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

func TestFlowspecEmptyNextHopProducerJSON(t *testing.T) {
	for _, afi := range []uint16{1, 2} {
		for _, safi := range []uint8{133, 134} {
			t.Run(fmt.Sprintf("%d/%d", afi, safi), func(t *testing.T) {
				components := []byte{3, 0x81, 6}
				if safi == 134 {
					components = append([]byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 7}, components...)
				}
				wire := append([]byte{byte(afi >> 8), byte(afi), safi, 0, 0, byte(len(components))}, components...)
				nlri, err := bgp.UnmarshalMPReachNLRI(wire, false, nil)
				if err != nil {
					t.Fatal(err)
				}
				p := NewProducer(&mockPublisher{}, false).(*producer)
				msgs, err := p.flowspec(nlri, 0, minimalPeerHeader(), minimalUpdate())
				if err != nil {
					t.Fatal(err)
				}
				if len(msgs) != 1 {
					t.Fatalf("records=%d", len(msgs))
				}
				if msgs[0].Nexthop != "" {
					t.Fatalf("published next-hop=%q", msgs[0].Nexthop)
				}
				data, err := json.Marshal(msgs[0])
				if err != nil {
					t.Fatal(err)
				}
				var raw map[string]json.RawMessage
				if err = json.Unmarshal(data, &raw); err != nil {
					t.Fatal(err)
				}
				if _, ok := raw["nexthop"]; ok {
					t.Fatalf("empty next-hop must be omitted: %s", data)
				}
				var got Flowspec
				if err = json.Unmarshal(data, &got); err != nil {
					t.Fatalf("typed reader rejects corrected producer JSON: %v; %s", err, data)
				}
				if got.Nexthop != "" || got.SpecHash != msgs[0].SpecHash || len(got.Spec) != 1 {
					t.Fatalf("unexpected typed record: %+v", got)
				}
			})
		}
	}
}

func TestFlowspecOptionalNextHopValidation(t *testing.T) {
	for _, tt := range []struct {
		name, value string
		bad         bool
	}{
		{"missing", "", false}, {"null", `,"nexthop":null`, false},
		{"nonempty", `,"nexthop":"192.0.2.1"`, false}, {"bad type", `,"nexthop":7`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := buildFlowspecJSON(t, nil)
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, "nexthop")
			data, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			data = append(append(data[:len(data)-1], []byte(tt.value)...), '}')
			var got Flowspec
			err = json.Unmarshal(data, &got)
			if (err != nil) != tt.bad {
				t.Fatalf("error=%v, want error=%v", err, tt.bad)
			}
			if tt.name == "nonempty" && got.Nexthop != "192.0.2.1" {
				t.Fatalf("next-hop=%q", got.Nexthop)
			}
		})
	}
}
