package bgpls

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestPrefixAttributeRangeJSON(t *testing.T) {
	tests := []struct {
		name      string
		proto     base.ProtoID
		wire      []byte
		wantRange string
		wantFlags byte
	}{
		{
			name:      "IS-IS range only",
			proto:     base.ISISL2,
			wire:      []byte{0x04, 0x87, 0, 4, 0xa8, 0, 0, 100},
			wantRange: `{"flags":{"f_flag":true,"m_flag":false,"s_flag":true,"d_flag":false,"a_flag":true},"range_size":100}`,
			wantFlags: 0xa8,
		},
		{
			name:      "OSPF range and prefix flags",
			proto:     base.OSPFv2,
			wire:      []byte{0x04, 0x87, 0, 4, 0x80, 0, 0x10, 0, 0x04, 0x92, 0, 1, 0x80},
			wantRange: `{"flags":{"ia_flag":true},"range_size":4096}`,
			wantFlags: 0x80,
		},
		{
			name:      "unknown protocol and Prefix SID",
			proto:     base.Direct,
			wire:      []byte{0x04, 0x87, 0, 16, 0x12, 0, 0, 5, 0x04, 0x86, 0, 8, 0, 128, 0, 0, 0, 0, 0, 42, 0x04, 0x92, 0, 1, 0x80},
			wantRange: `{"flags":{"flags":18},"range_size":5,"prefix_sid":[{"flags":{"flags":0},"algo":128,"prefix_sid":42}]}`,
			wantFlags: 0x12,
		},
		{
			name:  "malformed range and IS-IS prefix flags",
			proto: base.ISISL2,
			wire:  []byte{0x04, 0x87, 0, 3, 0x80, 0, 0, 0x04, 0x92, 0, 1, 0x80},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := UnmarshalBGPLSNLRI(tt.wire)
			if err != nil {
				t.Fatal(err)
			}
			prefixAttrs, err := attrs.GetPrefixAttrTLVs(tt.proto)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(prefixAttrs)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Range json.RawMessage `json:"range"`
			}
			if err := json.Unmarshal(payload, &got); err != nil {
				t.Fatal(err)
			}
			if string(got.Range) != tt.wantRange {
				t.Errorf("range = %s, want %s", got.Range, tt.wantRange)
			}
			var roundTrip PrefixAttrTLVs
			if err := json.Unmarshal(payload, &roundTrip); err != nil {
				t.Fatal(err)
			}
			if tt.wantRange == "" {
				if roundTrip.Range != nil {
					t.Fatalf("decoded range = %+v, want nil", roundTrip.Range)
				}
				return
			}
			if roundTrip.Range == nil || roundTrip.Range.Flags == nil || roundTrip.Range.Flags.GetRangeFlagsByte() != tt.wantFlags {
				t.Fatalf("decoded range = %+v, want flags %#x", roundTrip.Range, tt.wantFlags)
			}
			encoded, err := json.Marshal(&roundTrip)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != string(payload) {
				t.Errorf("round trip = %s, want %s", encoded, payload)
			}
		})
	}
}

func TestPrefixRangeRejectsMalformedNestedSIDFlags(t *testing.T) {
	var attrs PrefixAttrTLVs
	wire := []byte(`{"range":{"range_size":1,"prefix_sid":[{"flags":1,"algo":0,"prefix_sid":42}]}}`)
	if err := json.Unmarshal(wire, &attrs); err == nil {
		t.Fatal("malformed nested Prefix-SID flags decoded without error")
	}
}
