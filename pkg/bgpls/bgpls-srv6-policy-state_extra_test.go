package bgpls

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func makeSRv6BindingSIDTestValue() []byte {
	b := make([]byte, 36)
	b[0] = 0xe0 // B, U, and F flags
	for i := 0; i < 16; i++ {
		b[4+i] = byte(i + 1)
		b[20+i] = byte(16 - i)
	}
	return b
}

func appendSRPolicySubTLV(b []byte, typ uint16, value []byte) []byte {
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[0:2], typ)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(value)))
	b = append(b, header...)
	return append(b, value...)
}

func TestUnmarshalSRv6BindingSID(t *testing.T) {
	input := makeSRv6BindingSIDTestValue()
	input = appendSRPolicySubTLV(input, 1250, []byte{0x12, 0x34, 0x56, 0x78})
	input = appendSRPolicySubTLV(input, 1252, []byte{40, 24, 16, 0})
	input = appendSRPolicySubTLV(input, 65000, []byte{0xaa, 0xbb})

	got, err := UnmarshalSRv6BindingSID(input)
	if err != nil {
		t.Fatalf("UnmarshalSRv6BindingSID() error = %v", err)
	}
	if !got.FlagB || !got.FlagU || !got.FlagF {
		t.Fatalf("flags = B:%t U:%t F:%t, want all set", got.FlagB, got.FlagU, got.FlagF)
	}

	bsid := got.BSID
	if bsid == nil {
		t.Fatal("BSID is nil")
	}
	if !bytes.Equal(bsid.SID, input[4:20]) {
		t.Errorf("BSID = %x, want %x", bsid.SID, input[4:20])
	}
	specified := got.SBSID
	if specified == nil {
		t.Fatal("SBSID is nil")
	}
	if !bytes.Equal(specified.SID, input[20:36]) {
		t.Errorf("SBSID = %x, want %x", specified.SID, input[20:36])
	}

	if got.EndpointBehavior == nil {
		t.Fatal("EndpointBehavior is nil")
	}
	if got.EndpointBehavior.EndpointBehavior != 0x1234 || got.EndpointBehavior.Flag != 0x56 || got.EndpointBehavior.Algorithm != 0x78 {
		t.Errorf("EndpointBehavior = %+v, want behavior=0x1234 flag=0x56 algorithm=0x78", got.EndpointBehavior)
	}
	if got.SIDStructure == nil || got.SIDStructure.LBLength != 40 || got.SIDStructure.LNLength != 24 || got.SIDStructure.FunLength != 16 {
		t.Errorf("SIDStructure = %+v, want 40/24/16/0", got.SIDStructure)
	}
	if len(got.UnknownSubTLVs) != 1 {
		t.Fatalf("UnknownSubTLVs length = %d, want 1", len(got.UnknownSubTLVs))
	}
	if got.UnknownSubTLVs[0].Type != 65000 || !bytes.Equal(got.UnknownSubTLVs[0].Value, []byte{0xaa, 0xbb}) {
		t.Errorf("unknown sub-TLV = %+v, want type 65000 and value aabb", got.UnknownSubTLVs[0])
	}
}

func TestUnmarshalSRv6BindingSID_MalformedLengths(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "truncated fixed fields", input: make([]byte, 35)},
		{name: "truncated sub-TLV header", input: append(makeSRv6BindingSIDTestValue(), 0, 1, 0)},
		{name: "invalid endpoint behavior length", input: appendSRPolicySubTLV(makeSRv6BindingSIDTestValue(), 1250, []byte{1, 2, 3})},
		{name: "sub-TLV value exceeds buffer", input: append(makeSRv6BindingSIDTestValue(), 0, 1, 0, 4, 1, 2)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("UnmarshalSRv6BindingSID() panicked: %v", r)
				}
			}()
			if _, err := UnmarshalSRv6BindingSID(tt.input); err == nil {
				t.Fatal("UnmarshalSRv6BindingSID() error = nil, want error")
			}
		})
	}
}

func TestUnmarshalSRPolicyStateDecoders(t *testing.T) {
	t.Run("policy name", func(t *testing.T) {
		got, err := UnmarshalSRPolicyName([]byte("blue-policy"))
		if err != nil {
			t.Fatalf("UnmarshalSRPolicyName() error = %v", err)
		}
		if got.Name != "blue-policy" {
			t.Errorf("Name = %q, want %q", got.Name, "blue-policy")
		}
		if _, err := UnmarshalSRPolicyName(nil); err == nil {
			t.Fatal("UnmarshalSRPolicyName(nil) error = nil, want error")
		}
	})

	t.Run("bidirectional group identifier", func(t *testing.T) {
		input := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}
		got, err := UnmarshalSRBidirGroupConstrant(input)
		if err != nil {
			t.Fatalf("UnmarshalSRBidirGroupConstrant() error = %v", err)
		}
		if !got.FlagR || !got.FlagC || got.BidirectionalGroupID == nil || *got.BidirectionalGroupID != 0x01020304 {
			t.Errorf("decoded group constraint = %+v, want flags and ID 0x01020304", got)
		}
	})

	t.Run("bidirectional group PCEP object", func(t *testing.T) {
		input := []byte{0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
		got, err := UnmarshalSRBidirGroupConstrant(input)
		if err != nil {
			t.Fatalf("UnmarshalSRBidirGroupConstrant() error = %v", err)
		}
		if got.BidirectionalGroupID != nil || !bytes.Equal(got.PCEPAssociationObj, input[4:]) {
			t.Errorf("decoded PCEP association object = %+v, want %x", got, input[4:])
		}
	})

	t.Run("metric constraint exact length", func(t *testing.T) {
		input := make([]byte, 12)
		input[0] = byte(SRMetricAverageUnidirectionalDelay)
		input[1] = 0xf0
		binary.BigEndian.PutUint32(input[4:8], 100)
		binary.BigEndian.PutUint32(input[8:12], 200)
		got, err := UnmarshalSRMetricConstraint(input)
		if err != nil {
			t.Fatalf("UnmarshalSRMetricConstraint() error = %v", err)
		}
		if got.MetricType != SRMetricAverageUnidirectionalDelay || !got.FlagO || !got.FlagM || !got.FlagA || !got.FlagB || got.MetricMargin != 100 || got.MetricBound != 200 {
			t.Errorf("decoded metric constraint = %+v", got)
		}
		for _, length := range []int{0, 11, 13} {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("UnmarshalSRMetricConstraint() panicked for length %d: %v", length, r)
				}
			}()
			if _, err := UnmarshalSRMetricConstraint(make([]byte, length)); err == nil {
				t.Errorf("UnmarshalSRMetricConstraint(length %d) error = nil, want error", length)
			}
		}
	})

	t.Run("segment list bandwidth and identifier exact lengths", func(t *testing.T) {
		for name, decode := range map[string]func([]byte) error{
			"bandwidth": func(b []byte) error {
				_, err := UnmarshalSRSegmentListBandwidth(b)
				return err
			},
			"identifier": func(b []byte) error {
				_, err := UnmarshalSRSegmentListIdentifier(b)
				return err
			},
		} {
			t.Run(name, func(t *testing.T) {
				if err := decode([]byte{0, 0, 0, 1}); err != nil {
					t.Fatalf("valid 4-byte value returned error: %v", err)
				}
				for _, length := range []int{0, 3, 5} {
					if err := decode(make([]byte, length)); err == nil {
						t.Errorf("length %d returned nil error, want error", length)
					}
				}
			})
		}
	})
}

func TestGetSRPolicyState(t *testing.T) {
	constraints := make([]byte, 8)
	metric1 := make([]byte, 12)
	binary.BigEndian.PutUint32(metric1[4:8], 100)
	binary.BigEndian.PutUint32(metric1[8:12], 200)
	metric2 := make([]byte, 12)
	binary.BigEndian.PutUint32(metric2[4:8], 300)
	binary.BigEndian.PutUint32(metric2[8:12], 400)
	constraints = appendSRPolicySubTLV(constraints, SRMetricConstraintType, metric1)
	constraints = appendSRPolicySubTLV(constraints, SRMetricConstraintType, metric2)

	segmentList := make([]byte, 12)
	binary.BigEndian.PutUint32(segmentList[8:12], 50)
	bandwidth := make([]byte, 4)
	binary.BigEndian.PutUint32(bandwidth, math.Float32bits(1000))
	segmentList = appendSRPolicySubTLV(segmentList, SRSegmentListBandwidthType, bandwidth)
	segmentList = appendSRPolicySubTLV(segmentList, SRSegmentListIdentifierType, []byte{0, 0, 0, 7})

	state, err := (&NLRI{LS: []TLV{
		{Type: SRPolicyNameType, Value: []byte("blue-policy")},
		{Type: SRCandidatePathConstraintsType, Value: constraints},
		{Type: SRSegmentListType, Value: segmentList},
	}}).GetSRPolicyState()
	if err != nil {
		t.Fatalf("GetSRPolicyState() error = %v", err)
	}
	if state.PolicyName == nil || state.PolicyName.Name != "blue-policy" {
		t.Errorf("PolicyName = %+v, want blue-policy", state.PolicyName)
	}
	if state.Constraints == nil || len(state.Constraints.MetricConstraints) != 2 {
		t.Fatalf("MetricConstraints = %+v, want two entries", state.Constraints)
	}
	if state.Constraints.MetricConstraints[1].MetricMargin != 300 || state.Constraints.MetricConstraints[1].MetricBound != 400 {
		t.Errorf("second metric = %+v, want margin/bound 300/400", state.Constraints.MetricConstraints[1])
	}
	if len(state.SegmentLists) != 1 || len(state.SegmentLists[0].SubTLV) != 2 {
		t.Fatalf("SegmentLists = %+v, want one list with two sub-TLVs", state.SegmentLists)
	}
	if got, ok := state.SegmentLists[0].SubTLV[0].(*SRSegmentListBandwidth); !ok || got.Bandwidth != 1000 {
		t.Errorf("segment-list bandwidth = %#v, want 1000", state.SegmentLists[0].SubTLV[0])
	}
	if got, ok := state.SegmentLists[0].SubTLV[1].(*SRSegmentListIdentifier); !ok || got.Identifier != 7 {
		t.Errorf("segment-list identifier = %#v, want 7", state.SegmentLists[0].SubTLV[1])
	}
}

func TestGetSRPolicyStateWithAFlagClearSegmentDescriptor(t *testing.T) {
	label := make([]byte, 4)
	binary.BigEndian.PutUint32(label, uint32(16001)<<12)
	segment := []byte{byte(SegmentType1), 0x00, 0xe0, 0x00}
	segment = append(segment, label...)
	segment = append(segment, 0x00) // Type 1 Algorithm descriptor.

	segmentList := make([]byte, 12)
	segmentList = appendSRPolicySubTLV(segmentList, SRSegmentType, segment)
	state, err := (&NLRI{LS: []TLV{
		{Type: SRSegmentListType, Value: segmentList},
	}}).GetSRPolicyState()
	if err != nil {
		t.Fatalf("GetSRPolicyState() error = %v", err)
	}
	if len(state.SegmentLists) != 1 || len(state.SegmentLists[0].SubTLV) != 1 {
		t.Fatalf("SegmentLists = %+v, want one segment", state.SegmentLists)
	}
	got, ok := state.SegmentLists[0].SubTLV[0].(*SRSegment)
	if !ok {
		t.Fatalf("segment type = %T, want *SRSegment", state.SegmentLists[0].SubTLV[0])
	}
	if got.FlagA || got.SegmentDescriptor == nil {
		t.Fatalf("segment flags/descriptor = A:%t descriptor:%#v, want A:false and descriptor", got.FlagA, got.SegmentDescriptor)
	}
	desc, ok := got.SegmentDescriptor.(*SRType1Descriptor)
	if !ok || desc.Algorithm != 0 {
		t.Fatalf("segment descriptor = %#v, want Type 1 algorithm 0", got.SegmentDescriptor)
	}
}
