package message

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestPublishLSLinkLANSIDs(t *testing.T) {
	isisNeighbors := []byte{0, 1, 2, 3, 4, 5}
	ospfNeighbors := []byte{192, 0, 2, 45}
	srv6SID := []byte{0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12}
	structure := messageInterASTLV(1252, []byte{32, 16, 16, 0})
	unknown := messageInterASTLV(65000, []byte{0xaa, 0xbb})

	// RFC 9085 §2.2.2 and RFC 9514 §4.2 put the neighbor ID immediately before the SID.
	isisLabel := append(append([]byte{0xfc, 9, 0, 0}, isisNeighbors...), 0xf1, 0x23, 0x45)
	isisIndex := append(append([]byte{0x08, 0, 0, 0}, isisNeighbors...), 0, 0, 0, 0)
	ospfLabel := append(append([]byte{0xf8, 9, 0, 0}, ospfNeighbors...), 0x01, 0x23, 0x45)
	ospfIndex := append(append([]byte{0x10, 3, 0, 0}, ospfNeighbors...), 0x80, 0, 0, 0x01)
	isisEndX := append(append([]byte{0, 5, 0xa0, 128, 17, 0}, isisNeighbors...), srv6SID...)
	ospfEndX := append(append([]byte{0, 6, 0x40, 0, 3, 0}, ospfNeighbors...), srv6SID...)

	const (
		isisLabelJSON          = `{"flags":{"f_flag":true,"b_flag":true,"v_flag":true,"l_flag":true,"s_flag":true,"p_flag":true},"weight":9,"sid":74565,"neighbor_id":"0001.0203.0405"}`
		isisIndexJSON          = `{"flags":{"f_flag":false,"b_flag":false,"v_flag":false,"l_flag":false,"s_flag":true,"p_flag":false},"weight":0,"sid":0,"neighbor_id":"0001.0203.0405"}`
		ospfLabelJSON          = `{"flags":{"b_flag":true,"v_flag":true,"l_flag":true,"g_flag":true,"p_flag":true},"weight":9,"sid":74565,"neighbor_id":"192.0.2.45"}`
		ospfIndexJSON          = `{"flags":{"b_flag":false,"v_flag":false,"l_flag":false,"g_flag":true,"p_flag":false},"weight":3,"sid":2147483649,"neighbor_id":"192.0.2.45"}`
		isisEndXJSON           = `{"type":1107,"length":42,"endpoint_behavior":5,"flags":{"b_flag":true,"s_flag":false,"p_flag":true},"algorithm":128,"weight":17,"sid":"2001:db8:1::12","neighbor_id":"0001.0203.0405","sub_tlvs":[{"type":1252,"length":8,"locator_block_length":32,"locator_node_length":16,"function_length":16,"argument_length":0},{"type":65000,"length":6,"value":"qrs="}]}`
		isisEndXWithoutSubTLVs = `{"type":1107,"length":28,"endpoint_behavior":5,"flags":{"b_flag":true,"s_flag":false,"p_flag":true},"algorithm":128,"weight":17,"sid":"2001:db8:1::12","neighbor_id":"0001.0203.0405"}`
		ospfEndXJSON           = `{"type":1108,"length":26,"endpoint_behavior":6,"flags":{"b_flag":false,"s_flag":true,"p_flag":false},"algorithm":0,"weight":3,"sid":"2001:db8:1::12","neighbor_id":"192.0.2.45"}`
	)

	tests := []struct {
		name         string
		proto        base.ProtoID
		descriptors  []byte
		attributes   []byte
		wantAdj      string
		wantEndX     string
		wantP2PFlags string
		wantRawType  uint16
	}{
		{
			name:        "IS-IS L1 label and index with repeated End.X and sub-TLVs",
			proto:       base.ISISL1,
			descriptors: isisNeighbors,
			attributes: bytes.Join([][]byte{
				messageInterASTLV(1100, isisLabel),
				messageInterASTLV(1107, bytes.Join([][]byte{isisEndX, structure, unknown}, nil)),
				messageInterASTLV(1100, isisIndex[:12]),                                                 // Truncated label or index.
				messageInterASTLV(1107, append(bytes.Clone(isisEndX), 0x04, 0xe4, 0, 3, 32, 16, 16)),    // Invalid SID Structure length.
				messageInterASTLV(1107, append(bytes.Clone(isisEndX), 0x04, 0xe4, 0, 4, 32, 16, 80, 1)), // Invalid total width.
				messageInterASTLV(1107, append(bytes.Clone(isisEndX), 0x04, 0xe4, 0, 4, 32)),            // Truncated sub-TLV value.
				messageInterASTLV(1107, append(bytes.Clone(isisEndX), 0x04)),                            // Truncated sub-TLV header.
				messageInterASTLV(1107, append(bytes.Clone(isisEndX), 0, 0, 0, 0)),                      // Reserved sub-TLV type zero.
				messageInterASTLV(1108, ospfEndX),                                                       // Other protocol.
				messageInterASTLV(1100, isisIndex),
				messageInterASTLV(1107, isisEndX),
			}, nil),
			wantAdj:      "[" + isisLabelJSON + "," + isisIndexJSON + "]",
			wantEndX:     "[" + isisEndXJSON + "," + isisEndXWithoutSubTLVs + "]",
			wantP2PFlags: `{"f_flag":false,"b_flag":false,"v_flag":false,"l_flag":false,"s_flag":false,"p_flag":false}`,
			wantRawType:  1108,
		},
		{
			name:        "IS-IS L2 wrong label width and short End.X",
			proto:       base.ISISL2,
			descriptors: isisNeighbors,
			attributes: bytes.Join([][]byte{
				messageInterASTLV(1100, append(bytes.Clone(isisLabel), 0)),
				messageInterASTLV(1107, isisEndX[:27]),
				messageInterASTLV(1100, isisLabel),
			}, nil),
			wantAdj:      "[" + isisLabelJSON + "]",
			wantP2PFlags: `{"f_flag":false,"b_flag":false,"v_flag":false,"l_flag":false,"s_flag":false,"p_flag":false}`,
		},
		{
			name:        "OSPFv2 Router-ID and wrong-protocol End.X",
			proto:       base.OSPFv2,
			descriptors: ospfNeighbors,
			attributes: bytes.Join([][]byte{
				messageInterASTLV(1100, ospfIndex[:7]),
				messageInterASTLV(1100, ospfLabel),
				messageInterASTLV(1108, ospfEndX),
			}, nil),
			wantAdj:      "[" + ospfLabelJSON + "]",
			wantP2PFlags: `{"b_flag":false,"v_flag":false,"l_flag":false,"g_flag":false,"p_flag":false}`,
			wantRawType:  1108,
		},
		{
			name:        "OSPFv3 Router-ID and valid End.X after a short instance",
			proto:       base.OSPFv3,
			descriptors: ospfNeighbors,
			attributes: bytes.Join([][]byte{
				messageInterASTLV(1100, append([]byte{0x40}, ospfLabel[1:]...)), // V set, L clear.
				messageInterASTLV(1108, ospfEndX[:25]),
				messageInterASTLV(1107, isisEndX), // Other protocol, with a complete value.
				messageInterASTLV(1100, ospfIndex),
				messageInterASTLV(1108, ospfEndX),
			}, nil),
			wantAdj:      "[" + ospfIndexJSON + "]",
			wantEndX:     "[" + ospfEndXJSON + "]",
			wantP2PFlags: `{"b_flag":false,"v_flag":false,"l_flag":false,"g_flag":false,"p_flag":false}`,
			wantRawType:  1107,
		},
		{
			name:         "point-to-point SIDs only",
			proto:        base.ISISL2,
			descriptors:  isisNeighbors,
			wantP2PFlags: `{"f_flag":false,"b_flag":false,"v_flag":false,"l_flag":false,"s_flag":false,"p_flag":false}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// RFC 9552 §5.2.2: Link NLRI with local and remote node descriptors and link IDs.
			body := []byte{byte(tt.proto), 0, 0, 0, 0, 0, 0, 0, 7}
			local := bytes.Clone(tt.descriptors)
			local[len(local)-1]--
			nodeDescriptor := func(typ uint16, routerID []byte) []byte {
				var subTLVs []byte
				if tt.proto == base.OSPFv2 || tt.proto == base.OSPFv3 {
					subTLVs = messageInterASTLV(514, []byte{0, 0, 0, 0}) // Backbone area.
				}
				subTLVs = append(subTLVs, messageInterASTLV(515, routerID)...)
				return messageInterASTLV(typ, subTLVs)
			}
			body = append(body, nodeDescriptor(256, local)...)
			remote := bytes.Clone(tt.descriptors)
			remote[len(remote)-1]++
			switch tt.proto {
			case base.ISISL1, base.ISISL2:
				remote = append(remote, 1) // Pseudonode ID.
			case base.OSPFv2:
				remote = append(remote, 192, 0, 2, 46) // DR interface address.
			case base.OSPFv3:
				remote = append(remote, 0, 0, 0, 42) // DR interface ID.
			}
			body = append(body, nodeDescriptor(257, remote)...)
			body = append(body, messageInterASTLV(258, []byte{0, 0, 0, 1, 0, 0, 0, 2})...)
			reach := append([]byte{0x40, 4, 71, 4, 192, 0, 2, 1, 0}, messageInterASTLV(2, body)...)

			// Baseline p2p attributes and an independent link property.
			ls := bytes.Join([][]byte{
				messageInterASTLV(1099, []byte{0, 4, 0, 0, 0, 0, 0, 123}),
				tt.attributes,
				messageInterASTLV(1106, append(append([]byte{0, 5, 0xa0, 0, 11, 0}, srv6SID...), structure...)),
				messageInterASTLV(1092, []byte{0, 0, 0, 23}),
			}, nil)
			attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe8} // ORIGIN and AS_PATH
			attrs = append(attrs, lsPathAttribute(14, reach)...)
			attrs = append(attrs, lsPathAttribute(29, ls)...)
			rm := eorWire(t, nil, attrs, nil)
			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			p.produceRouteMessage(bmp.Message{PeerHeader: minimalPeerHeader(), Payload: rm})
			if len(publisher.msgs) != 1 || publisher.msgs[0].msgType != bmp.LSLinkMsg {
				t.Fatalf("published %v, want one Link event", publisher.msgs)
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal(publisher.msgs[0].payload, &got); err != nil {
				t.Fatal(err)
			}
			var link LSLink
			if err := json.Unmarshal(publisher.msgs[0].payload, &link); err != nil {
				t.Fatalf("unmarshal Link event: %v", err)
			}
			if tt.wantRawType == 0 {
				if len(link.UnknownBGPLSTLVs) != 0 {
					t.Errorf("modeled LAN types unexpectedly included in raw TLVs: %v", link.UnknownBGPLSTLVs)
				}
			} else if len(link.UnknownBGPLSTLVs) != 1 || link.UnknownBGPLSTLVs[0].Type != tt.wantRawType {
				t.Errorf("raw TLVs = %v, want only unexpected type %d", link.UnknownBGPLSTLVs, tt.wantRawType)
			}
			roundTrip, err := json.Marshal(link)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]json.RawMessage
			if err := json.Unmarshal(roundTrip, &decoded); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"ls_lan_adjacency_sid", "srv6_lan_endx_sid"} {
				if !bytes.Equal(got[field], decoded[field]) {
					t.Errorf("%s changed after LSLink JSON round trip: got %s, want %s", field, decoded[field], got[field])
				}
			}
			want := map[string]string{
				"ls_lan_adjacency_sid": tt.wantAdj,
				"srv6_lan_endx_sid":    tt.wantEndX,
				"ls_adjacency_sid":     `[{"flags":` + tt.wantP2PFlags + `,"weight":4,"sid":123}]`,
				"srv6_endx_sid":        `[{"endpoint_behavior":5,"flags":{"b_flag":true,"s_flag":false,"p_flag":true},"algorithm":0,"weight":11,"sid":"2001:db8:1::12","sub_tlvs":[{"type":1252,"length":8,"locator_block_length":32,"locator_node_length":16,"function_length":16,"argument_length":0}]}]`,
				"te_default_metric":    "23",
			}
			for key, expected := range want {
				raw, present := got[key]
				if expected == "" {
					if present {
						t.Errorf("%s unexpectedly present: %s", key, raw)
					}
					continue
				}
				if !present {
					t.Errorf("%s absent, want %s", key, expected)
					continue
				}
				var actual any
				if err := json.Unmarshal(raw, &actual); err != nil {
					t.Fatal(err)
				}
				var wantValue any
				if err := json.Unmarshal([]byte(expected), &wantValue); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(actual, wantValue) {
					t.Errorf("%s = %s, want %s", key, got[key], expected)
				}
			}
		})
	}
}
