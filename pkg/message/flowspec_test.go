package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/flowspec"
)

func TestFlowspecUnmarshalJSON_PrefixSpec(t *testing.T) {
	tests := []struct {
		name     string
		specType int
	}{
		{name: "Type1_DestinationPrefix", specType: 1},
		{name: "Type2_SourcePrefix", specType: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := buildFlowspecJSON(t, []map[string]interface{}{
				{
					"type":       float64(tt.specType),
					"prefix_len": float64(24),
					"prefix":     "abc",
				},
			})
			fs := &Flowspec{}
			if err := fs.UnmarshalJSON(input); err != nil {
				t.Fatalf("UnmarshalJSON failed: %v", err)
			}
			if len(fs.Spec) != 1 {
				t.Fatalf("expected 1 spec, got %d", len(fs.Spec))
			}
			ps, ok := fs.Spec[0].(*flowspec.PrefixSpec)
			if !ok {
				t.Fatalf("expected *flowspec.PrefixSpec, got %T", fs.Spec[0])
			}
			if ps.SpecType != uint8(tt.specType) {
				t.Errorf("SpecType = %d, want %d", ps.SpecType, tt.specType)
			}
			if ps.PrefixLength != 24 {
				t.Errorf("PrefixLength = %d, want 24", ps.PrefixLength)
			}
		})
	}
}

func TestFlowspecUnmarshalJSON_GenericSpec(t *testing.T) {
	tests := []struct {
		name     string
		specType int
	}{
		{name: "Type3_IPProtocol", specType: 3},
		{name: "Type4_Port", specType: 4},
		{name: "Type5_DestinationPort", specType: 5},
		{name: "Type6_SourcePort", specType: 6},
		{name: "Type7_ICMPType", specType: 7},
		{name: "Type8_ICMPCode", specType: 8},
		{name: "Type9_TCPFlags", specType: 9},
		{name: "Type10_PacketLength", specType: 10},
		{name: "Type11_DSCP", specType: 11},
		{name: "Type12_Fragment", specType: 12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := buildFlowspecJSON(t, []map[string]interface{}{
				{
					"type": float64(tt.specType),
					"op_val_pairs": []interface{}{
						map[string]interface{}{
							"operator": map[string]interface{}{
								"value_length":    float64(1),
								"end_of_list_bit": true,
								"equal":           true,
							},
							"value": "\x06",
						},
					},
				},
			})
			fs := &Flowspec{}
			if err := fs.UnmarshalJSON(input); err != nil {
				t.Fatalf("UnmarshalJSON failed: %v", err)
			}
			if len(fs.Spec) != 1 {
				t.Fatalf("expected 1 spec, got %d", len(fs.Spec))
			}
			gs, ok := fs.Spec[0].(*flowspec.GenericSpec)
			if !ok {
				t.Fatalf("expected *flowspec.GenericSpec, got %T", fs.Spec[0])
			}
			if gs.SpecType != uint8(tt.specType) {
				t.Errorf("SpecType = %d, want %d", gs.SpecType, tt.specType)
			}
			if len(gs.OpVal) != 1 {
				t.Fatalf("expected 1 op_val_pair, got %d", len(gs.OpVal))
			}
			if gs.OpVal[0].Op == nil {
				t.Fatal("operator should not be nil")
			}
			if !gs.OpVal[0].Op.EOLBit {
				t.Error("EOLBit should be true")
			}
			if !gs.OpVal[0].Op.EQBit {
				t.Error("EQBit should be true")
			}
		})
	}
}

func TestFlowspecUnmarshalJSON_MultipleSpecs(t *testing.T) {
	input := buildFlowspecJSON(t, []map[string]interface{}{
		{
			"type":       float64(1),
			"prefix_len": float64(24),
			"prefix":     "abc",
		},
		{
			"type": float64(3),
			"op_val_pairs": []interface{}{
				map[string]interface{}{
					"operator": map[string]interface{}{
						"value_length":    float64(1),
						"end_of_list_bit": true,
					},
					"value": "\x11",
				},
			},
		},
	})
	fs := &Flowspec{}
	if err := fs.UnmarshalJSON(input); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if len(fs.Spec) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(fs.Spec))
	}
	if _, ok := fs.Spec[0].(*flowspec.PrefixSpec); !ok {
		t.Errorf("spec[0]: expected *flowspec.PrefixSpec, got %T", fs.Spec[0])
	}
	if _, ok := fs.Spec[1].(*flowspec.GenericSpec); !ok {
		t.Errorf("spec[1]: expected *flowspec.GenericSpec, got %T", fs.Spec[1])
	}
}

func TestFlowspecUnmarshalJSON_NoSpec(t *testing.T) {
	input := buildFlowspecJSON(t, nil)
	fs := &Flowspec{}
	if err := fs.UnmarshalJSON(input); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if fs.Spec != nil {
		t.Errorf("expected nil spec, got %v", fs.Spec)
	}
}

// buildFlowspecJSON builds a minimal Flowspec JSON payload with the given specs.
func buildFlowspecJSON(t *testing.T, specs []map[string]interface{}) []byte {
	t.Helper()
	obj := map[string]interface{}{
		"action":           "add",
		"spec_hash":        "abc123",
		"base_attrs":       map[string]interface{}{},
		"is_ipv4":          true,
		"is_nexthop_ipv4":  true,
		"nexthop":          "10.0.0.1",
		"peer_asn":         float64(65000),
		"router_ip":        "192.168.1.1",
		"timestamp":        "2026-01-01T00:00:00Z",
	}
	if specs != nil {
		obj["spec"] = specs
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("failed to build test JSON: %v", err)
	}
	return b
}
