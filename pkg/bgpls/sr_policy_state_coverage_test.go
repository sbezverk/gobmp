package bgpls

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSRPolicyAccessors(t *testing.T) {
	nlri := &NLRI{LS: []TLV{
		{Type: 65000, Value: []byte{1}},
		{Type: SRPolicyNameType, Value: []byte("blue")},
		{Type: SRv6BindingSIDType, Value: makeSRv6BindingSIDTestValue()},
	}}

	name, err := nlri.GetSRPolicyName()
	if err != nil || name == nil || name.Name != "blue" {
		t.Fatalf("GetSRPolicyName() = %#v, %v; want blue", name, err)
	}
	binding, err := nlri.GetSRv6BindingSID()
	if err != nil || binding == nil || binding.BSID == nil {
		t.Fatalf("GetSRv6BindingSID() = %#v, %v; want decoded binding SID", binding, err)
	}

	if _, err := (&NLRI{}).GetSRPolicyName(); err == nil {
		t.Fatal("GetSRPolicyName() error = nil for missing TLV")
	}
	if _, err := (&NLRI{}).GetSRv6BindingSID(); err == nil {
		t.Fatal("GetSRv6BindingSID() error = nil for missing TLV")
	}
}

func TestSRBindingSIDRejectsFlagLengthMismatch(t *testing.T) {
	for _, input := range [][]byte{
		{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // D flag requires 36 bytes.
		make([]byte, 36),                        // D flag clear requires 12 bytes.
	} {
		if _, err := UnmarshalSRBindingSID(input); err == nil {
			t.Errorf("UnmarshalSRBindingSID(%d bytes) error = nil, want error", len(input))
		}
	}
}

func TestSRPolicyConstraintSubTLVRejectsMalformedKnownTypes(t *testing.T) {
	for _, typ := range []uint16{
		SRAffinityConstraintType,
		SRSRLGConstraintType,
		SRBandwidthConstraintType,
		SRDisjointGroupConstraintType,
		SRBidirectionalGroupConstraintType,
		SRMetricConstraintType,
	} {
		if _, err := UnmarshalSRCandidatePathConstraintsSubTLV(appendSRPolicySubTLV(nil, typ, []byte{0})); err == nil {
			t.Errorf("constraint sub-TLV %d error = nil, want malformed-value error", typ)
		}
	}
}

func TestSRSegmentListSubTLVRejectsMalformedKnownTypes(t *testing.T) {
	for _, typ := range []uint16{SRSegmentType, SRSegmentListMetricType, SRSegmentListBandwidthType, SRSegmentListIdentifierType} {
		if _, err := UnmarshalSRSegmentListSubTLV(appendSRPolicySubTLV(nil, typ, []byte{0})); err == nil {
			t.Errorf("segment-list sub-TLV %d error = nil, want malformed-value error", typ)
		}
	}
}

func TestSRBidirGroupConstraintRejectsTruncatedValue(t *testing.T) {
	if _, err := UnmarshalSRBidirGroupConstrant([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("truncated bidirectional group constraint returned nil error")
	}
}

func TestGetSRPolicyStateDecodesEveryKnownTLV(t *testing.T) {
	binding := []byte{0x40, 0, 0, 0, 0, 0x10, 0, 0, 0, 0x20, 0, 0}
	candidateState := []byte{5, 0, 0x40, 0, 0, 0, 0, 100}
	constraints := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	segmentList := make([]byte, 12)

	state, err := (&NLRI{LS: []TLV{
		{Type: BindingSIDType, Value: binding},
		{Type: SRv6BindingSIDType, Value: makeSRv6BindingSIDTestValue()},
		{Type: SRCandidatePathStateType, Value: candidateState},
		{Type: SRCandidatePathNameType, Value: []byte("candidate")},
		{Type: SRPolicyNameType, Value: []byte("policy")},
		{Type: SRCandidatePathConstraintsType, Value: constraints},
		{Type: SRSegmentListType, Value: segmentList},
	}}).GetSRPolicyState()
	if err != nil {
		t.Fatalf("GetSRPolicyState() error = %v", err)
	}
	if state.BindingSID == nil || state.SRv6BindingSID == nil ||
		state.CandidatePathState == nil || state.CandidatePathName == nil ||
		state.PolicyName == nil || state.Constraints == nil || len(state.SegmentLists) != 1 {
		t.Fatalf("GetSRPolicyState() omitted a decoded TLV: %+v", state)
	}
	if !state.HasData() {
		t.Fatal("HasData() = false for populated state")
	}
}

func TestGetSRPolicyStateEmptyAndMalformed(t *testing.T) {
	var nilNLRI *NLRI
	if state, err := nilNLRI.GetSRPolicyState(); err == nil || state != nil {
		t.Fatalf("nil GetSRPolicyState() = %#v, %v; want nil and error", state, err)
	}

	state, err := (&NLRI{LS: []TLV{{Type: 65000, Value: []byte{1}}}}).GetSRPolicyState()
	if err != nil || state == nil || state.HasData() {
		t.Fatalf("unknown-only state = %#v, %v; want empty state", state, err)
	}
	if (*SRPolicyState)(nil).HasData() {
		t.Fatal("nil HasData() = true")
	}
	if (&SRPolicyState{}).HasData() {
		t.Fatal("empty HasData() = true")
	}

	if state, err := (&NLRI{LS: []TLV{{Type: BindingSIDType, Value: []byte{1}}}}).GetSRPolicyState(); err == nil || state != nil {
		t.Fatalf("malformed state = %#v, %v; want nil and error", state, err)
	}
}

func TestGetSRPolicyStateUnknownTLV(t *testing.T) {
	value := []byte{0x01, 0x02, 0x03}
	state, err := (&NLRI{LS: []TLV{{Type: 65000, Value: value}}}).GetSRPolicyState()
	if err != nil {
		t.Fatalf("GetSRPolicyState() error = %v", err)
	}
	if len(state.UnknownTLV) != 1 {
		t.Fatalf("UnknownTLV length = %d, want 1", len(state.UnknownTLV))
	}
	if state.UnknownTLV[0].Type != 65000 || state.UnknownTLV[0].Length != uint16(len(value)) {
		t.Fatalf("UnknownTLV metadata = %+v, want type 65000 and length %d", state.UnknownTLV[0], len(value))
	}
	value[0] = 0xff
	if state.UnknownTLV[0].Value[0] != 0x01 {
		t.Fatal("UnknownTLV value aliases the input TLV")
	}

	oversized, err := (&NLRI{LS: []TLV{{Type: 65001, Value: make([]byte, 1<<16)}}}).GetSRPolicyState()
	if err != nil {
		t.Fatalf("GetSRPolicyState() oversized unknown TLV error = %v", err)
	}
	if len(oversized.UnknownTLV) != 0 {
		t.Fatalf("oversized UnknownTLV was retained: %+v", oversized.UnknownTLV)
	}
}

func TestSRPolicyStateSubTLVJSONRoundTrip(t *testing.T) {
	id := uint32(7)
	tests := []struct {
		name  string
		value SRCandidatePathConstraintsSubTLV
		new   func() SRCandidatePathConstraintsSubTLV
	}{
		{
			name:  "bidirectional group",
			value: &SRBidirectionalGroupConstraint{FlagR: true, BidirectionalGroupID: &id},
			new:   func() SRCandidatePathConstraintsSubTLV { return &SRBidirectionalGroupConstraint{} },
		},
		{
			name:  "metric",
			value: &SRMetricConstraint{MetricType: 1, FlagA: true, MetricMargin: 10, MetricBound: 20},
			new:   func() SRCandidatePathConstraintsSubTLV { return &SRMetricConstraint{} },
		},
		{
			name:  "bandwidth",
			value: &SRSegmentListBandwidth{Bandwidth: 12.5},
			new:   func() SRCandidatePathConstraintsSubTLV { return &SRSegmentListBandwidth{} },
		},
		{
			name:  "identifier",
			value: &SRSegmentListIdentifier{Identifier: 42},
			new:   func() SRCandidatePathConstraintsSubTLV { return &SRSegmentListIdentifier{} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			decoded := tt.new()
			if err := decoded.UnmarshalJSON(encoded); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if !reflect.DeepEqual(decoded, tt.value) {
				t.Fatalf("JSON round trip = %#v, want %#v", decoded, tt.value)
			}
		})
	}
}
