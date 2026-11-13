package bgpls

import (
	"encoding/json"
	"maps"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestPrefixAttrTLVs_MarshalOSPFv3Flags(t *testing.T) {
	tests := []struct {
		name  string
		value byte
		want  map[string]bool
	}{
		{
			name:  "set and clear flags",
			value: 0x29,
			want: map[string]bool{
				"n_flag": true, "dn_flag": false, "p_flag": true, "la_flag": false, "nu_flag": true,
			},
		},
		{
			name:  "zero flags",
			value: 0,
			want: map[string]bool{
				"n_flag": false, "dn_flag": false, "p_flag": false, "la_flag": false, "nu_flag": false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// RFC 9085 §2.3.2 defines TLV 1170 and uses the NLRI Protocol-ID to interpret it.
			ls, err := UnmarshalBGPLSNLRI([]byte{0x04, 0x92, 0x00, 0x01, tt.value})
			if err != nil {
				t.Fatalf("unmarshal BGP-LS attribute: %v", err)
			}
			attrs, err := ls.GetPrefixAttrTLVs(base.OSPFv3)
			if err != nil {
				t.Fatalf("get prefix attributes: %v", err)
			}
			wire, err := json.Marshal(attrs)
			if err != nil {
				t.Fatalf("marshal prefix attributes: %v", err)
			}
			var result struct {
				Flags map[string]bool `json:"flags"`
			}
			if err := json.Unmarshal(wire, &result); err != nil {
				t.Fatalf("unmarshal prefix attributes JSON: %v", err)
			}
			if !maps.Equal(result.Flags, tt.want) {
				t.Errorf("flags = %v, want %v", result.Flags, tt.want)
			}
		})
	}
}
