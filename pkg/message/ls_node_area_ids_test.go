package message

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestProcessMPUpdate_LS71_ISISAreaIDs(t *testing.T) {
	area := lsSPFTLV{1027, []byte{0x49, 0x00, 0x01}}
	short := lsSPFTLV{1027, []byte{0x49}}
	long := lsSPFTLV{1027, []byte{0x49, 0x00, 0xab, 0x01}}
	maxLength := lsSPFTLV{1027, []byte{0x49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}}
	empty := lsSPFTLV{1027, nil}
	tooLong := lsSPFTLV{1027, make([]byte, 14)}
	tests := []struct {
		name       string
		protocol   base.ProtoID
		attributes *bgp.Update
		wantLegacy string
		wantAreas  []string
	}{
		{"single area", base.ISISL1, testLSUpdate(area), "49.0001", []string{"490001"}},
		{"multiple area lengths in wire order including a duplicate", base.ISISL2, testLSUpdate(area, short, long, area), "49.00014949.00ab,0149.0001", []string{"490001", "49", "4900ab01", "490001"}},
		{"empty and oversized area TLVs beside a valid maximum-length area", base.ISISL2, testLSUpdate(empty, tooLong, maxLength), "00.0000,00.0000,00.0000,00.0000,00.0049.0000,00.0000,00.0000,00.0000,01", []string{"49000000000000000000000001"}},
		{"empty area", base.ISISL2, testLSUpdate(empty), "", nil},
		{"no area TLV", base.ISISL2, testLSUpdate(lsSPFTLV{1026, []byte("node")}), "", nil},
		{"missing BGP-LS attribute", base.ISISL2, &bgp.Update{}, "", nil},
		{"truncated BGP-LS attribute", base.ISISL2, &bgp.Update{PathAttributes: []bgp.PathAttribute{
			{AttributeType: 29, Attribute: []byte{0x04, 0x03, 0, 3, 0x49}},
		}}, "", nil},
		{"OSPF keeps the descriptor area ID", base.OSPFv2, testLSUpdate(area), "7", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descriptor := []byte{
				0x01, 0x00, 0x00, 0x0a, // Local Node Descriptors
				0x02, 0x03, 0x00, 0x06, 0, 0, 0, 0, 0, 1, // IS-IS IGP Router-ID
			}
			if tt.protocol == base.OSPFv2 {
				descriptor = []byte{
					0x01, 0x00, 0x00, 0x10, // Local Node Descriptors
					0x02, 0x02, 0x00, 0x04, 0, 0, 0, 7, // OSPF Area-ID
					0x02, 0x03, 0x00, 0x04, 192, 0, 2, 1, // OSPF IGP Router-ID
				}
			}
			// AFI 16388, SAFI 71, next hop 192.0.2.1, and a Node NLRI.
			wire := []byte{0x40, 0x04, 71, 4, 192, 0, 2, 1, 0, 0, 1, 0, byte(9 + len(descriptor)), byte(tt.protocol)}
			wire = append(wire, make([]byte, 8)...) // Identifier
			wire = append(wire, descriptor...)

			nlri, err := bgp.UnmarshalMPReachNLRI(wire, false, nil)
			if err != nil {
				t.Fatalf("UnmarshalMPReachNLRI: %v", err)
			}
			rec := &recordingPublisher{}
			p := &producer{publisher: rec}
			p.processMPUpdate(nlri, 0, newPeerHeader(), tt.attributes)
			if len(rec.msgs) != 1 || rec.msgs[0].msgType != bmp.LSNodeMsg {
				t.Fatalf("expected one LS Node publication, got %+v", rec.msgs)
			}

			var fields map[string]json.RawMessage
			if err := json.Unmarshal(rec.msgs[0].payload, &fields); err != nil {
				t.Fatalf("unmarshal LS Node JSON: %v", err)
			}
			var legacy string
			if err := json.Unmarshal(fields["area_id"], &legacy); err != nil || legacy != tt.wantLegacy {
				t.Errorf("area_id = %s, want %q (error: %v)", fields["area_id"], tt.wantLegacy, err)
			}
			encoded, present := fields["isis_area_ids"]
			if tt.wantAreas == nil {
				if present {
					t.Errorf("isis_area_ids = %s, want field omitted", encoded)
				}
				return
			}
			var areas []string
			if err := json.Unmarshal(encoded, &areas); err != nil || !slices.Equal(areas, tt.wantAreas) {
				t.Errorf("isis_area_ids = %s, want %q (error: %v)", encoded, tt.wantAreas, err)
			}
		})
	}
}
