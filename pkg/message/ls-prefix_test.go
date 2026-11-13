package message

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/sr"
)

func TestRoundTripLSPrefix(t *testing.T) {
	original := &LSPrefix{
		Key:        "Key",
		ID:         "ID",
		Rev:        "Rev",
		ProtocolID: base.ISISL1,
		PrefixAttrTLVs: &bgpls.PrefixAttrTLVs{
			LSPrefixSID: []*sr.PrefixSIDTLV{
				{
					Flags: &sr.ISISFlags{
						RFlag: false,
						NFlag: true,
						PFlag: false,
						EFlag: false,
						VFlag: false,
						LFlag: false,
					},
					Algorithm: 129,
					SID:       20007,
				},
			},
		},
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("TestRoundTripLSPrefix Marshal failed with error: %+v but supposed to succeed", err)
	}

	recovered := &LSPrefix{}
	if err := json.Unmarshal(b, recovered); err != nil {
		t.Fatalf("TestRoundTripLSPrefix Unmarshal failed with error: %+v but supposed to succeed", err)
	}
	if !reflect.DeepEqual(original, recovered) {
		t.Logf("Differences: %+v", deep.Equal(original, recovered))
		t.Fatalf("TestRoundTripLSPrefix failed as original %+v does not match recovered: %+v", *original, *recovered)
	}
}

// RFC 9085 §§2.3.3–2.3.4 define two independent Prefix Attribute TLVs.
func TestLSPrefixSourceRouterIDsWire(t *testing.T) {
	generic4 := messageInterASTLV(1171, []byte{192, 0, 2, 1})
	generic6 := messageInterASTLV(1171, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	ospf := messageInterASTLV(1174, []byte{198, 51, 100, 2})
	badGeneric := messageInterASTLV(1171, []byte{192, 0, 2})
	badOSPF := messageInterASTLV(1174, []byte{198, 51, 100})
	ospfv2WithFlags := append(messageInterASTLV(1170, []byte{0x80}), generic4...)
	ospfv2WithFlags = append(ospfv2WithFlags, ospf...)
	ospfv3WithFlags := append(messageInterASTLV(1170, []byte{0x01}), generic6...)
	ospfv3WithFlags = append(ospfv3WithFlags, ospf...)
	tests := []struct {
		name string
		tlvs []byte
		ipv6 bool
		want map[string]string
	}{
		{"generic IPv4", generic4, false, map[string]string{
			"source_router_id": "192.0.2.1", "source_router_identifier": "192.0.2.1",
		}},
		{"generic IPv6", generic6, true, map[string]string{
			"source_router_id": "2001:db8::1", "source_router_identifier": "2001:db8::1",
		}},
		{"OSPF only", ospf, false, map[string]string{
			"source_router_id": "198.51.100.2", "source_ospf_router_id": "198.51.100.2",
		}},
		{"1171 then 1174 with OSPFv2 flags", ospfv2WithFlags, false, map[string]string{
			"source_router_id": "198.51.100.2", "source_router_identifier": "192.0.2.1", "source_ospf_router_id": "198.51.100.2",
		}},
		{"1174 then 1171", append(append([]byte(nil), ospf...), generic4...), false, map[string]string{
			"source_router_id": "198.51.100.2", "source_router_identifier": "192.0.2.1", "source_ospf_router_id": "198.51.100.2",
		}},
		{"invalid generic with valid OSPF", append(append([]byte(nil), badGeneric...), ospf...), false, map[string]string{
			"source_router_id": "198.51.100.2", "source_ospf_router_id": "198.51.100.2",
		}},
		{"invalid OSPF with valid generic", append(append([]byte(nil), badOSPF...), generic4...), false, map[string]string{
			"source_router_identifier": "192.0.2.1",
		}},
		{"OSPFv3 with flags", ospfv3WithFlags, true, map[string]string{
			"source_router_id": "198.51.100.2", "source_router_identifier": "2001:db8::1", "source_ospf_router_id": "198.51.100.2",
		}},
		{"both invalid", append(append([]byte(nil), badGeneric...), badOSPF...), false, nil},
		{"both absent", nil, false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proto, nlriType := base.OSPFv2, uint16(3)
			reachability := []byte{24, 203, 0, 113}
			if tt.ipv6 {
				proto, nlriType = base.OSPFv3, 4
				reachability = []byte{32, 0x20, 1, 0x0d, 0xb8}
			}
			node := messageInterASTLV(256, messageInterASTLV(515, []byte{192, 0, 2, 100}))
			prefix := append([]byte{byte(proto), 0, 0, 0, 0, 0, 0, 0, 0}, node...)
			prefix = append(prefix, messageInterASTLV(264, []byte{1})...) // OSPF Route Type
			prefix = append(prefix, messageInterASTLV(265, reachability)...)
			// ORIGIN and AS_PATH accompany the BGP-LS MP_REACH.
			attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe8}
			attrs = append(attrs, dPathReach(16388, 71, []byte{192, 0, 2, 9}, messageInterASTLV(nlriType, prefix))...)
			if len(tt.tlvs) != 0 {
				attrs = append(attrs, lsPathAttribute(29, tt.tlvs)...)
			}
			recorder := &recordingPublisher{}
			p := NewProducer(recorder, true).(*producer)
			p.produceRouteMessage(bmp.Message{
				PeerHeader: makePeerHeader(t, bmp.PeerType0, 0),
				Payload:    eorWire(t, nil, attrs, nil),
			})
			if len(recorder.msgs) != 1 || recorder.msgs[0].msgType != bmp.LSPrefixMsg {
				t.Fatalf("published = %+v, want one BGP-LS prefix", recorder.msgs)
			}

			wire := recorder.msgs[0].payload
			checkJSON := func(wire []byte) {
				t.Helper()
				var got struct {
					OSPFRouteType  uint8                      `json:"ospf_route_type"`
					PrefixAttrTLVs map[string]json.RawMessage `json:"prefix_attr_tlvs"`
				}
				if err := json.Unmarshal(wire, &got); err != nil {
					t.Fatalf("decode emitted JSON: %v", err)
				}
				if got.OSPFRouteType != 1 {
					t.Errorf("ospf_route_type = %d, want 1", got.OSPFRouteType)
				}
				if tt.want == nil && got.PrefixAttrTLVs != nil {
					t.Errorf("prefix_attr_tlvs should be omitted: %s", wire)
				}
				for _, key := range []string{"source_router_id", "source_router_identifier", "source_ospf_router_id"} {
					raw, present := got.PrefixAttrTLVs[key]
					want, wantPresent := tt.want[key]
					if present != wantPresent {
						t.Errorf("%s presence = %t, want %t", key, present, wantPresent)
					}
					if !present {
						continue
					}
					var id string
					if err := json.Unmarshal(raw, &id); err != nil || id != want {
						t.Errorf("%s = %s, want %q (decode error: %v)", key, raw, want, err)
					}
				}
			}
			checkJSON(wire)

			var recovered LSPrefix
			if err := json.Unmarshal(wire, &recovered); err != nil {
				t.Fatalf("decode LSPrefix: %v", err)
			}
			roundTrip, err := json.Marshal(&recovered)
			if err != nil {
				t.Fatalf("re-encode LSPrefix: %v", err)
			}
			checkJSON(roundTrip)
		})
	}
}

func TestLSPrefix_OSPFForwardingAddress(t *testing.T) {
	tests := []struct {
		name  string
		proto base.ProtoID
		value []byte
		want  string
	}{
		{"IPv4", base.OSPFv2, []byte{192, 0, 2, 9}, "192.0.2.9"},
		{"IPv6", base.OSPFv3, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, "2001:db8::9"},
		{"absent", base.OSPFv2, nil, ""},
		{"invalid address length", base.OSPFv2, []byte{192, 0, 2}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prfx := &base.PrefixNLRI{
				ProtocolID: tt.proto,
				LocalNode:  &base.NodeDescriptor{},
				Prefix: &base.PrefixDescriptor{
					PrefixTLV: map[uint16]base.TLV{
						265: {Type: 265, Length: 1, Value: []byte{0}},
					},
				},
			}
			update := &bgp.Update{}
			if tt.value != nil {
				// RFC 9552 §5.3.3.5 permits IPv4 and IPv6 forwarding addresses in TLV 1156.
				attr := buildBGPLSAttrWithOpaque(1156, tt.value)
				update.PathAttributes = []bgp.PathAttribute{
					{AttributeType: 29, AttributeLength: uint16(len(attr)), Attribute: attr},
				}
			}
			msg, err := (&producer{}).lsPrefix(prfx, "", 0, newPeerHeader(), update, tt.proto == base.OSPFv2)
			if err != nil {
				t.Fatalf("lsPrefix() error = %v", err)
			}
			wire, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("marshal prefix: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(wire, &fields); err != nil {
				t.Fatalf("unmarshal prefix JSON: %v", err)
			}
			got, present := fields["ospf_fwd_addr"]
			if tt.want == "" {
				if present {
					t.Errorf("ospf_fwd_addr = %s, want absent", got)
				}
				return
			}
			if string(got) != strconv.Quote(tt.want) {
				t.Errorf("ospf_fwd_addr = %s, want %q", got, tt.want)
			}
		})
	}
}
