package bgpls

import (
	"encoding/json"
	"errors"
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
			var decoded PrefixAttrTLVs
			if err := json.Unmarshal(wire, &decoded); err != nil {
				t.Fatalf("unmarshal OSPFv3 flags: %v", err)
			}
			flags, ok := decoded.Flags.(*OSPFv3Flags)
			if !ok || flags == nil || flags.GetPrefixAttrFlagsByte() != tt.value {
				t.Errorf("decoded flags = %#v, want OSPFv3 flags %#02x", decoded.Flags, tt.value)
			}
		})
	}
}

type unsupportedPrefixFlags struct{}

func (unsupportedPrefixFlags) GetPrefixAttrFlagsByte() byte { return 0 }

func TestPrefixAttrTLVs_MarshalOmitsNonOSPFv3FlagsInFallback(t *testing.T) {
	for _, tt := range []struct {
		name  string
		flags PrefixAttrFlags
	}{
		{"absent flags", nil},
		{"typed nil flags", (*OSPFv3Flags)(nil)},
		{"unrecognized implementation", unsupportedPrefixFlags{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := json.Marshal(&PrefixAttrTLVs{
				Flags:          tt.flags,
				SourceRouterID: "192.0.2.1",
			})
			if err != nil {
				t.Fatal(err)
			}
			const want = `{"source_router_id":"192.0.2.1"}`
			if string(payload) != want {
				t.Errorf("JSON = %s, want %s", payload, want)
			}
		})
	}
}

func TestPrefixAttrTLVs_UnmarshalFlagsShape(t *testing.T) {
	for _, tt := range []struct {
		name     string
		flags    string
		wantType bool
	}{
		{"null flags", "null", false},
		{"number instead of object", "1", true},
		{"array instead of object", "[]", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const routerID = "192.0.2.1"
			input := `{"flags":` + tt.flags + `,"source_router_id":"` + routerID + `"}`
			attrs := PrefixAttrTLVs{SourceRouterID: "192.0.2.2"}
			err := json.Unmarshal([]byte(input), &attrs)
			if tt.wantType {
				var typeErr *json.UnmarshalTypeError
				if !errors.As(err, &typeErr) {
					t.Fatalf("error = %v, want JSON type error", err)
				}
				if attrs.SourceRouterID != "192.0.2.2" {
					t.Errorf("failed decode changed source router ID to %q", attrs.SourceRouterID)
				}
				return
			}
			if err != nil || attrs.Flags != nil || attrs.SourceRouterID != routerID {
				t.Errorf("decoded %+v, error %v, want nil flags and source router ID %s", attrs, err, routerID)
			}
		})
	}
}
