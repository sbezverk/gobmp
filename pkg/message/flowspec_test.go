package message

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/evpn"
	"github.com/sbezverk/gobmp/pkg/flowspec"
	"github.com/sbezverk/gobmp/pkg/ls"
	"github.com/sbezverk/gobmp/pkg/mcastvpn"
	"github.com/sbezverk/gobmp/pkg/rtc"
	"github.com/sbezverk/gobmp/pkg/srpolicy"
	"github.com/sbezverk/gobmp/pkg/vpls"
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

// flowspecMockNLRI is a minimal bgp.MPNLRI for flowspec producer tests.
type flowspecMockNLRI struct {
	allNLRI []*flowspec.NLRI
	err     error
	isIPv6  bool
}

func (m *flowspecMockNLRI) GetAllFlowspecNLRI() ([]*flowspec.NLRI, error) { return m.allNLRI, m.err }
func (m *flowspecMockNLRI) GetFlowspecNLRI() (*flowspec.NLRI, error)      { return nil, nil }
func (m *flowspecMockNLRI) GetNextHop() string                            { return "10.0.0.1" }
func (m *flowspecMockNLRI) IsIPv6NLRI() bool                              { return m.isIPv6 }
func (m *flowspecMockNLRI) IsNextHopIPv6() bool                           { return m.isIPv6 }
func (m *flowspecMockNLRI) GetAFISAFIType() int                           { return 27 }
func (m *flowspecMockNLRI) GetNLRILU() (*base.MPNLRI, error)              { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIUnicast() (*base.MPNLRI, error)         { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIMulticast() (*base.MPNLRI, error)       { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIEVPN() (*evpn.Route, error)             { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIVPLS() (*vpls.Route, error)             { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIL3VPN() (*base.MPNLRI, error)           { return nil, nil }
func (m *flowspecMockNLRI) GetNLRI71() (*ls.NLRI71, error)                { return nil, nil }
func (m *flowspecMockNLRI) GetNLRI73() (*srpolicy.NLRI73, error)          { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIMCASTVPN() (*mcastvpn.Route, error)     { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIMVPN() (*mcastvpn.Route, error)         { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIRTC() (*rtc.Route, error)               { return nil, nil }

// minimalPeerHeader returns a PerPeerHeader usable in producer tests.
func minimalPeerHeader() *bmp.PerPeerHeader {
	return &bmp.PerPeerHeader{
		PeerType:          0,
		PeerAS:            65000,
		PeerAddress:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		PeerBGPID:         []byte{10, 0, 0, 1},
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}
}

// minimalUpdate returns a bgp.Update usable in producer tests.
func minimalUpdate() *bgp.Update {
	return &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{
			ASPath: []uint32{65000},
		},
	}
}

// parseOneNLRI parses a minimal IPv4 flowspec NLRI from wire bytes and returns it.
func parseOneNLRI(t *testing.T) *flowspec.NLRI {
	t.Helper()
	// 10.0.0.0/8 destination prefix
	nlri, err := flowspec.UnmarshalFlowspecNLRI([]byte{0x03, 0x01, 0x08, 0x0a})
	if err != nil {
		t.Fatalf("failed to parse test NLRI: %v", err)
	}
	return nlri
}

func TestFlowspecProducer_AddSingleNLRI(t *testing.T) {
	nlri := parseOneNLRI(t)
	mock := &flowspecMockNLRI{allNLRI: []*flowspec.NLRI{nlri}}
	p := &producer{speakerIP: "10.1.1.1"}

	msgs, err := p.flowspec(mock, 0, minimalPeerHeader(), minimalUpdate())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Action != "add" {
		t.Errorf("action = %q, want %q", msgs[0].Action, "add")
	}
	if msgs[0].SpecHash == "" {
		t.Error("SpecHash should not be empty for a real NLRI")
	}
}

func TestFlowspecProducer_AddMultiNLRI(t *testing.T) {
	nlri1 := parseOneNLRI(t)
	// 192.168.0.0/16 destination prefix
	nlri2, err := flowspec.UnmarshalFlowspecNLRI([]byte{0x04, 0x01, 0x10, 0xc0, 0xa8})
	if err != nil {
		t.Fatalf("failed to parse second NLRI: %v", err)
	}
	mock := &flowspecMockNLRI{allNLRI: []*flowspec.NLRI{nlri1, nlri2}}
	p := &producer{speakerIP: "10.1.1.1"}

	msgs, err := p.flowspec(mock, 0, minimalPeerHeader(), minimalUpdate())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
}

func TestFlowspecProducer_WithdrawAll(t *testing.T) {
	tests := []struct {
		name         string
		isIPv6       bool
		wantSpecHash string
	}{
		{"ipv4 withdraw-all", false, "withdraw-all:10.0.0.1:0:0"},
		{"ipv6 withdraw-all", true, "ipv6:withdraw-all:10.0.0.1:0:0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &flowspecMockNLRI{allNLRI: nil, isIPv6: tt.isIPv6}
			p := &producer{speakerIP: "10.1.1.1"}

			msgs, err := p.flowspec(mock, 1, minimalPeerHeader(), minimalUpdate())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(msgs) != 1 {
				t.Fatalf("expected 1 withdraw-all message, got %d", len(msgs))
			}
			if msgs[0].SpecHash != tt.wantSpecHash {
				t.Errorf("SpecHash = %q, want %q", msgs[0].SpecHash, tt.wantSpecHash)
			}
			if msgs[0].Action != "del" {
				t.Errorf("action = %q, want %q", msgs[0].Action, "del")
			}
		})
	}
}

func TestFlowspecProducer_UnknownOp(t *testing.T) {
	mock := &flowspecMockNLRI{}
	p := &producer{speakerIP: "10.1.1.1"}

	_, err := p.flowspec(mock, 99, minimalPeerHeader(), minimalUpdate())
	if err == nil {
		t.Error("expected error for unknown operation, got nil")
	}
}

func TestFlowspecProducer_GetAllFlowspecNLRI_Error(t *testing.T) {
	mock := &flowspecMockNLRI{err: errors.New("simulated parse failure")}
	p := &producer{speakerIP: "10.1.1.1"}

	_, err := p.flowspec(mock, 0, minimalPeerHeader(), minimalUpdate())
	if err == nil {
		t.Error("expected error propagation from GetAllFlowspecNLRI, got nil")
	}
}

// TestFlowspecUnmarshalJSON_PrefixOffset verifies the prefix_offset field is round-tripped
// through JSON UnmarshalJSON (makePrefixSpec branch).
func TestFlowspecUnmarshalJSON_PrefixOffset(t *testing.T) {
	input := buildFlowspecJSON(t, []map[string]interface{}{
		{
			"type":          float64(1),
			"prefix_len":    float64(48),
			"prefix_offset": float64(16),
			"prefix":        "abc",
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
	if ps.Offset != 16 {
		t.Errorf("Offset = %d, want 16", ps.Offset)
	}
}

// TestFlowspecUnmarshalJSON_PrefixOffset_NonNumber verifies that a non-numeric prefix_offset returns an error.
func TestFlowspecUnmarshalJSON_PrefixOffset_NonNumber(t *testing.T) {
	input := buildFlowspecJSON(t, []map[string]interface{}{
		{
			"type":          float64(1),
			"prefix_len":    float64(48),
			"prefix_offset": "not-a-number",
			"prefix":        "abc",
		},
	})
	fs := &Flowspec{}
	if err := fs.UnmarshalJSON(input); err == nil {
		t.Error("expected error for non-numeric prefix_offset, got nil")
	}
}

// TestFlowspecUnmarshalJSON_PrefixOffset_Fractional verifies that a fractional prefix_offset returns an error.
func TestFlowspecUnmarshalJSON_PrefixOffset_Fractional(t *testing.T) {
	input := buildFlowspecJSON(t, []map[string]interface{}{
		{
			"type":          float64(1),
			"prefix_len":    float64(48),
			"prefix_offset": float64(16.9),
			"prefix":        "abc",
		},
	})
	fs := &Flowspec{}
	if err := fs.UnmarshalJSON(input); err == nil {
		t.Error("expected error for fractional prefix_offset, got nil")
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
