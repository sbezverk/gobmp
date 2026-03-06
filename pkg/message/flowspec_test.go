package message

import (
	"encoding/json"
	"fmt"
	"strings"
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

// flowspecMockNLRI implements bgp.MPNLRI for flowspec producer tests.
type flowspecMockNLRI struct {
	allNLRI  []*flowspec.NLRI
	allErr   error
	nextHop  string
	isIPv6   bool
}

func (m *flowspecMockNLRI) GetAFISAFIType() int                          { return 27 }
func (m *flowspecMockNLRI) GetNLRILU() (*base.MPNLRI, error)             { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIUnicast() (*base.MPNLRI, error)        { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIMulticast() (*base.MPNLRI, error)      { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIEVPN() (*evpn.Route, error)            { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIVPLS() (*vpls.Route, error)            { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIL3VPN() (*base.MPNLRI, error)          { return nil, nil }
func (m *flowspecMockNLRI) GetNLRI71() (*ls.NLRI71, error)               { return nil, nil }
func (m *flowspecMockNLRI) GetNLRI73() (*srpolicy.NLRI73, error)         { return nil, nil }
func (m *flowspecMockNLRI) GetFlowspecNLRI() (*flowspec.NLRI, error)     { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIMCASTVPN() (*mcastvpn.Route, error)    { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIMVPN() (*mcastvpn.Route, error)        { return nil, nil }
func (m *flowspecMockNLRI) GetNLRIRTC() (*rtc.Route, error)              { return nil, nil }
func (m *flowspecMockNLRI) GetNextHop() string                           { return m.nextHop }
func (m *flowspecMockNLRI) IsIPv6NLRI() bool                             { return m.isIPv6 }
func (m *flowspecMockNLRI) IsNextHopIPv6() bool                          { return m.isIPv6 }
func (m *flowspecMockNLRI) GetAllFlowspecNLRI() ([]*flowspec.NLRI, error) {
	return m.allNLRI, m.allErr
}

func testPeerHeader() *bmp.PerPeerHeader {
	return &bmp.PerPeerHeader{
		PeerType:          0,
		PeerAS:            65000,
		PeerAddress:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1},
		PeerBGPID:         []byte{10, 0, 0, 1},
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}
}

func TestFlowspecProducer_MultipleNLRIs(t *testing.T) {
	nlri1 := &flowspec.NLRI{
		Length:   5,
		SpecHash: "hash1",
		Spec:     []flowspec.Spec{&flowspec.PrefixSpec{SpecType: 1, PrefixLength: 24, Prefix: []byte{10, 0, 1}}},
	}
	nlri2 := &flowspec.NLRI{
		Length:   3,
		SpecHash: "hash2",
		Spec:     []flowspec.Spec{&flowspec.GenericSpec{SpecType: 3}},
	}
	mock := &flowspecMockNLRI{
		allNLRI: []*flowspec.NLRI{nlri1, nlri2},
		nextHop: "10.0.0.2",
	}
	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{ASPath: []uint32{65000, 65001}},
	}
	p := &producer{speakerIP: "192.168.1.1"}

	msgs, err := p.flowspec(mock, 0, testPeerHeader(), update)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if msgs[0].SpecHash != "hash1" {
		t.Errorf("msgs[0].SpecHash = %q, want %q", msgs[0].SpecHash, "hash1")
	}
	if msgs[1].SpecHash != "hash2" {
		t.Errorf("msgs[1].SpecHash = %q, want %q", msgs[1].SpecHash, "hash2")
	}
	if msgs[0].Action != "add" {
		t.Errorf("msgs[0].Action = %q, want %q", msgs[0].Action, "add")
	}
	if msgs[0].OriginAS != 65001 {
		t.Errorf("msgs[0].OriginAS = %d, want 65001", msgs[0].OriginAS)
	}
	if msgs[0].Nexthop != "10.0.0.2" {
		t.Errorf("msgs[0].Nexthop = %q, want %q", msgs[0].Nexthop, "10.0.0.2")
	}
	if !msgs[0].IsIPv4 {
		t.Error("msgs[0].IsIPv4 should be true")
	}
}

func TestFlowspecProducer_WithdrawAll(t *testing.T) {
	mock := &flowspecMockNLRI{
		allNLRI: nil,
		nextHop: "10.0.0.2",
	}
	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{},
	}
	p := &producer{speakerIP: "192.168.1.1"}

	msgs, err := p.flowspec(mock, 1, testPeerHeader(), update)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 withdraw-all message, got %d", len(msgs))
	}
	if msgs[0].Action != "del" {
		t.Errorf("Action = %q, want %q", msgs[0].Action, "del")
	}
	if !strings.HasPrefix(msgs[0].SpecHash, "withdraw-all:") {
		t.Errorf("SpecHash = %q, expected withdraw-all: prefix", msgs[0].SpecHash)
	}
	if msgs[0].Spec != nil {
		t.Errorf("Spec should be nil for withdraw-all, got %v", msgs[0].Spec)
	}
}

func TestFlowspecProducer_UnknownOperation(t *testing.T) {
	mock := &flowspecMockNLRI{}
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}
	p := &producer{}

	_, err := p.flowspec(mock, 99, testPeerHeader(), update)
	if err == nil {
		t.Fatal("expected error for unknown operation, got nil")
	}
	if !strings.Contains(err.Error(), "unknown operation") {
		t.Errorf("error = %q, expected 'unknown operation'", err.Error())
	}
}

func TestFlowspecProducer_GetAllFlowspecNLRIError(t *testing.T) {
	mock := &flowspecMockNLRI{
		allErr: fmt.Errorf("not implemented"),
	}
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}
	p := &producer{}

	_, err := p.flowspec(mock, 0, testPeerHeader(), update)
	if err == nil {
		t.Fatal("expected error from GetAllFlowspecNLRI, got nil")
	}
}

func TestFlowspecProducer_SingleNLRI(t *testing.T) {
	nlri1 := &flowspec.NLRI{
		Length:   5,
		SpecHash: "single-hash",
		Spec:     []flowspec.Spec{&flowspec.PrefixSpec{SpecType: 2, PrefixLength: 16, Prefix: []byte{172, 16}}},
	}
	mock := &flowspecMockNLRI{
		allNLRI: []*flowspec.NLRI{nlri1},
		nextHop: "10.0.0.3",
	}
	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{},
	}
	p := &producer{speakerIP: "10.1.1.1"}

	msgs, err := p.flowspec(mock, 1, testPeerHeader(), update)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Action != "del" {
		t.Errorf("Action = %q, want %q", msgs[0].Action, "del")
	}
	if msgs[0].SpecHash != "single-hash" {
		t.Errorf("SpecHash = %q, want %q", msgs[0].SpecHash, "single-hash")
	}
	if msgs[0].RouterIP != "10.1.1.1" {
		t.Errorf("RouterIP = %q, want %q", msgs[0].RouterIP, "10.1.1.1")
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
