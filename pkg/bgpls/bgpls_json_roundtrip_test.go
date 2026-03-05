package bgpls

import (
	"bytes"
	"encoding/json"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// JSON round-trip tests for SID types
// ─────────────────────────────────────────────────────────────────────────────

func TestMPLSLabelSID_JSON(t *testing.T) {
	orig := &MPLSLabelSID{Label: 12345, TC: 3, S: true, TTL: 64}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &MPLSLabelSID{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Label != orig.Label {
		t.Errorf("Label = %d, want %d", got.Label, orig.Label)
	}
	if got.TC != orig.TC {
		t.Errorf("TC = %d, want %d", got.TC, orig.TC)
	}
	if got.S != orig.S {
		t.Errorf("S = %v, want %v", got.S, orig.S)
	}
	if got.TTL != orig.TTL {
		t.Errorf("TTL = %d, want %d", got.TTL, orig.TTL)
	}
}

func TestMPLSLabelSID_JSON_ZeroValues(t *testing.T) {
	orig := &MPLSLabelSID{}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &MPLSLabelSID{Label: 99, TC: 7, S: true, TTL: 255}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Label != 0 || got.TC != 0 || got.S != false || got.TTL != 0 {
		t.Errorf("zero-value round-trip failed: got %+v", got)
	}
}

func TestSRv6SID_JSON(t *testing.T) {
	orig := &SRv6SID{SID: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRv6SID{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if !bytes.Equal(got.SID, orig.SID) {
		t.Errorf("SID = %v, want %v", got.SID, orig.SID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON round-trip tests for SegmentDescriptor types
// ─────────────────────────────────────────────────────────────────────────────

func TestSRType1Descriptor_JSON(t *testing.T) {
	orig := &SRType1Descriptor{Algorithm: 7}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRType1Descriptor{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Algorithm != orig.Algorithm {
		t.Errorf("Algorithm = %d, want %d", got.Algorithm, orig.Algorithm)
	}
}

func TestSRType3Descriptor_JSON(t *testing.T) {
	orig := &SRType3Descriptor{
		IPv4NodeAddress: []byte{10, 0, 0, 1},
		Algorithm:       5,
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRType3Descriptor{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if !bytes.Equal(got.IPv4NodeAddress, orig.IPv4NodeAddress) {
		t.Errorf("IPv4NodeAddress = %v, want %v", got.IPv4NodeAddress, orig.IPv4NodeAddress)
	}
	if got.Algorithm != orig.Algorithm {
		t.Errorf("Algorithm = %d, want %d", got.Algorithm, orig.Algorithm)
	}
}

func TestSRType4Descriptor_JSON(t *testing.T) {
	orig := &SRType4Descriptor{
		IPv6NodeAddress: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Algorithm:       3,
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRType4Descriptor{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if !bytes.Equal(got.IPv6NodeAddress, orig.IPv6NodeAddress) {
		t.Errorf("IPv6NodeAddress = %v, want %v", got.IPv6NodeAddress, orig.IPv6NodeAddress)
	}
	if got.Algorithm != orig.Algorithm {
		t.Errorf("Algorithm = %d, want %d", got.Algorithm, orig.Algorithm)
	}
}

func TestSRType5Descriptor_JSON(t *testing.T) {
	orig := &SRType5Descriptor{
		LocalNodeIPv4:    []byte{192, 168, 1, 1},
		LocalInterfaceID: 1001,
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRType5Descriptor{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if !bytes.Equal(got.LocalNodeIPv4, orig.LocalNodeIPv4) {
		t.Errorf("LocalNodeIPv4 = %v, want %v", got.LocalNodeIPv4, orig.LocalNodeIPv4)
	}
	if got.LocalInterfaceID != orig.LocalInterfaceID {
		t.Errorf("LocalInterfaceID = %d, want %d", got.LocalInterfaceID, orig.LocalInterfaceID)
	}
}

func TestSRType6Descriptor_JSON(t *testing.T) {
	orig := &SRType6Descriptor{
		LocalInterfaceIPv4:  []byte{10, 1, 1, 1},
		RemoteInterfaceIPv4: []byte{10, 1, 1, 2},
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRType6Descriptor{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if !bytes.Equal(got.LocalInterfaceIPv4, orig.LocalInterfaceIPv4) {
		t.Errorf("LocalInterfaceIPv4 = %v, want %v", got.LocalInterfaceIPv4, orig.LocalInterfaceIPv4)
	}
	if !bytes.Equal(got.RemoteInterfaceIPv4, orig.RemoteInterfaceIPv4) {
		t.Errorf("RemoteInterfaceIPv4 = %v, want %v", got.RemoteInterfaceIPv4, orig.RemoteInterfaceIPv4)
	}
}

func TestSRType7Descriptor_JSON(t *testing.T) {
	orig := &SRType7Descriptor{
		LocalNodeIPv6:     []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		LocalInterfaceID:  100,
		RemoteNodeIPv6:    []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		RemoteInterfaceID: 200,
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRType7Descriptor{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if !bytes.Equal(got.LocalNodeIPv6, orig.LocalNodeIPv6) {
		t.Errorf("LocalNodeIPv6 = %v, want %v", got.LocalNodeIPv6, orig.LocalNodeIPv6)
	}
	if got.LocalInterfaceID != orig.LocalInterfaceID {
		t.Errorf("LocalInterfaceID = %d, want %d", got.LocalInterfaceID, orig.LocalInterfaceID)
	}
	if !bytes.Equal(got.RemoteNodeIPv6, orig.RemoteNodeIPv6) {
		t.Errorf("RemoteNodeIPv6 = %v, want %v", got.RemoteNodeIPv6, orig.RemoteNodeIPv6)
	}
	if got.RemoteInterfaceID != orig.RemoteInterfaceID {
		t.Errorf("RemoteInterfaceID = %d, want %d", got.RemoteInterfaceID, orig.RemoteInterfaceID)
	}
}

func TestSRType8Descriptor_JSON(t *testing.T) {
	orig := &SRType8Descriptor{
		LocalInterfaceIPv6:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		RemoteInterfaceIPv6: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRType8Descriptor{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if !bytes.Equal(got.LocalInterfaceIPv6, orig.LocalInterfaceIPv6) {
		t.Errorf("LocalInterfaceIPv6 = %v, want %v", got.LocalInterfaceIPv6, orig.LocalInterfaceIPv6)
	}
	if !bytes.Equal(got.RemoteInterfaceIPv6, orig.RemoteInterfaceIPv6) {
		t.Errorf("RemoteInterfaceIPv6 = %v, want %v", got.RemoteInterfaceIPv6, orig.RemoteInterfaceIPv6)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON round-trip tests for SRSegment and SRSegmentListMetric
// ─────────────────────────────────────────────────────────────────────────────

// SRSegment.UnmarshalJSON decodes the sid field as json.RawMessage and
// instantiates the concrete SID type based on segment_type.
func TestSRSegment_JSON_NoSID(t *testing.T) {
	orig := &SRSegment{
		Segment: SegmentType1,
		FlagS:   false,
		FlagE:   true,
		FlagV:   false,
		FlagR:   true,
		FlagA:   false,
		SID:     nil,
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRSegment{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Segment != orig.Segment {
		t.Errorf("Segment = %v, want %v", got.Segment, orig.Segment)
	}
	if got.FlagE != orig.FlagE || got.FlagR != orig.FlagR {
		t.Errorf("flags mismatch: got FlagE=%v FlagR=%v, want FlagE=%v FlagR=%v",
			got.FlagE, got.FlagR, orig.FlagE, orig.FlagR)
	}
	if got.SID != nil {
		t.Errorf("SID should be nil when FlagS=false, got %v", got.SID)
	}
}

func TestSRSegment_JSON_MPLSsid(t *testing.T) {
	orig := &SRSegment{
		Segment: SegmentType1,
		FlagS:   true,
		FlagE:   false,
		FlagV:   false,
		FlagR:   false,
		FlagA:   false,
		SID:     &MPLSLabelSID{Label: 300, TC: 2, S: false, TTL: 128},
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRSegment{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Segment != orig.Segment {
		t.Errorf("Segment = %v, want %v", got.Segment, orig.Segment)
	}
	mplsSID, ok := got.SID.(*MPLSLabelSID)
	if !ok {
		t.Fatalf("SID is %T, want *MPLSLabelSID", got.SID)
	}
	wantSID := orig.SID.(*MPLSLabelSID)
	if mplsSID.Label != wantSID.Label || mplsSID.TC != wantSID.TC || mplsSID.S != wantSID.S || mplsSID.TTL != wantSID.TTL {
		t.Errorf("SID = %+v, want %+v", mplsSID, wantSID)
	}
}

func TestSRSegment_JSON_SRv6sid(t *testing.T) {
	orig := &SRSegment{
		Segment: SegmentType2,
		FlagS:   true,
		FlagE:   false,
		FlagV:   false,
		FlagR:   false,
		FlagA:   false,
		SID:     &SRv6SID{SID: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRSegment{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	srv6SID, ok := got.SID.(*SRv6SID)
	if !ok {
		t.Fatalf("SID is %T, want *SRv6SID", got.SID)
	}
	wantSID := orig.SID.(*SRv6SID)
	if !bytes.Equal(srv6SID.SID, wantSID.SID) {
		t.Errorf("SID = %v, want %v", srv6SID.SID, wantSID.SID)
	}
}

func TestSRSegment_JSON_AllFlags(t *testing.T) {
	orig := &SRSegment{
		Segment: SegmentType3,
		FlagS:   true,
		FlagE:   true,
		FlagV:   true,
		FlagR:   true,
		FlagA:   true,
		SID:     &MPLSLabelSID{Label: 100, TC: 1, S: true, TTL: 64},
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRSegment{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if !got.FlagS || !got.FlagE || !got.FlagV || !got.FlagR || !got.FlagA {
		t.Errorf("one or more flags not restored: %+v", got)
	}
	if got.Segment != SegmentType3 {
		t.Errorf("Segment = %v, want %v", got.Segment, SegmentType3)
	}
	if _, ok := got.SID.(*MPLSLabelSID); !ok {
		t.Errorf("SID is %T, want *MPLSLabelSID", got.SID)
	}
}

func TestSRSegmentListMetric_JSON(t *testing.T) {
	orig := &SRSegmentListMetric{
		Metric: SRMetricTE,
		FlagM:  true,
		FlagA:  false,
		FlagB:  true,
		FlagV:  false,
		Margin: 100,
		Bound:  200,
		Value:  300,
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRSegmentListMetric{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Metric != orig.Metric {
		t.Errorf("Metric = %d, want %d", got.Metric, orig.Metric)
	}
	if got.FlagM != orig.FlagM || got.FlagA != orig.FlagA || got.FlagB != orig.FlagB || got.FlagV != orig.FlagV {
		t.Errorf("flags mismatch: got %+v, want %+v", got, orig)
	}
	if got.Margin != orig.Margin || got.Bound != orig.Bound || got.Value != orig.Value {
		t.Errorf("metric values mismatch: got Margin=%d Bound=%d Value=%d, want %d %d %d",
			got.Margin, got.Bound, got.Value, orig.Margin, orig.Bound, orig.Value)
	}
}

func TestSRSegmentListMetric_JSON_ZeroValues(t *testing.T) {
	orig := &SRSegmentListMetric{}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRSegmentListMetric{Metric: SRMetricTE, FlagM: true, Margin: 99, Bound: 99, Value: 99}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Metric != 0 || got.FlagM || got.Margin != 0 || got.Bound != 0 || got.Value != 0 {
		t.Errorf("zero-value round-trip failed: got %+v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalJSON error-path coverage (bad JSON input triggers error return)
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalJSON_ErrorPaths(t *testing.T) {
	bad := []byte("not-valid-json{{{")
	t.Run("MPLSLabelSID", func(t *testing.T) {
		if err := json.Unmarshal(bad, &MPLSLabelSID{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRv6SID", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRv6SID{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRType1Descriptor", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRType1Descriptor{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRType3Descriptor", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRType3Descriptor{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRType4Descriptor", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRType4Descriptor{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRType5Descriptor", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRType5Descriptor{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRType6Descriptor", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRType6Descriptor{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRType7Descriptor", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRType7Descriptor{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRType8Descriptor", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRType8Descriptor{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRAffinityConstraint", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRAffinityConstraint{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRSRLGConstraint", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRSRLGConstraint{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRBandwidthConstraint", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRBandwidthConstraint{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRDisjointGroupConstraint", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRDisjointGroupConstraint{}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("SRSegmentListMetric", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRSegmentListMetric{}); err == nil {
			t.Error("expected error")
		}
	})
	// Outer JSON invalid for SRSegment
	t.Run("SRSegment_outer", func(t *testing.T) {
		if err := json.Unmarshal(bad, &SRSegment{}); err == nil {
			t.Error("expected error")
		}
	})
	// Valid outer JSON but SID is a string, not an object — triggers MPLS SID decode error
	t.Run("SRSegment_bad_mpls_sid", func(t *testing.T) {
		input := []byte(`{"segment_type":1,"s_flag":true,"e_flag":false,"v_flag":false,"r_flag":false,"a_flag":false,"sid":"not-an-object"}`)
		if err := json.Unmarshal(input, &SRSegment{}); err == nil {
			t.Error("expected error decoding non-object SID as MPLSLabelSID")
		}
	})
	// Valid outer JSON but SID is a string — triggers SRv6 SID decode error
	t.Run("SRSegment_bad_srv6_sid", func(t *testing.T) {
		input := []byte(`{"segment_type":2,"s_flag":true,"e_flag":false,"v_flag":false,"r_flag":false,"a_flag":false,"sid":"not-an-object"}`)
		if err := json.Unmarshal(input, &SRSegment{}); err == nil {
			t.Error("expected error decoding non-object SID as SRv6SID")
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalSRSegmentListSubTLV
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalSRSegmentListSubTLV(t *testing.T) {
	t.Run("too short (3 bytes)", func(t *testing.T) {
		if _, err := UnmarshalSRSegmentListSubTLV(make([]byte, 3)); err == nil {
			t.Error("expected error for too-short input")
		}
	})

	t.Run("truncated value", func(t *testing.T) {
		// header claims length=8 but only 4 bytes follow
		b := []byte{0x04, 0xB6, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00}
		if _, err := UnmarshalSRSegmentListSubTLV(b); err == nil {
			t.Error("expected error for truncated value")
		}
	})

	t.Run("SRSegmentType type1 no flags", func(t *testing.T) {
		// SRSegmentType = 1206 = 0x04B6; segment bytes: type=1, reserved, flags=0, reserved
		b := []byte{
			0x04, 0xB6, 0x00, 0x04, // sub-TLV type=1206, length=4
			0x01, 0x00, 0x00, 0x00, // SegmentType1, no flags
		}
		got, err := UnmarshalSRSegmentListSubTLV(b)
		if err != nil {
			t.Fatalf("UnmarshalSRSegmentListSubTLV() error = %v", err)
		}
		if _, ok := got[SRSegmentType]; !ok {
			t.Error("SRSegmentType key missing from result")
		}
	})

	t.Run("SRSegmentListMetricType", func(t *testing.T) {
		// SRSegmentListMetricType = 1207 = 0x04B7; exactly 16 bytes of metric
		b := []byte{
			0x04, 0xB7, 0x00, 0x10, // sub-TLV type=1207, length=16
			0x02,       // metric = SRMetricTE
			0x80,       // FlagM=1
			0x00, 0x00, // reserved
			0x00, 0x00, 0x00, 0x64, // margin=100
			0x00, 0x00, 0x00, 0xC8, // bound=200
			0x00, 0x00, 0x01, 0x2C, // value=300
		}
		got, err := UnmarshalSRSegmentListSubTLV(b)
		if err != nil {
			t.Fatalf("UnmarshalSRSegmentListSubTLV() error = %v", err)
		}
		tlv, ok := got[SRSegmentListMetricType]
		if !ok {
			t.Fatal("SRSegmentListMetricType key missing from result")
		}
		m, ok := tlv.(*SRSegmentListMetric)
		if !ok {
			t.Fatalf("value type = %T, want *SRSegmentListMetric", tlv)
		}
		if m.Metric != SRMetricTE {
			t.Errorf("Metric = %d, want %d", m.Metric, SRMetricTE)
		}
		if !m.FlagM {
			t.Error("FlagM should be true")
		}
		if m.Margin != 100 || m.Bound != 200 || m.Value != 300 {
			t.Errorf("Margin/Bound/Value = %d/%d/%d, want 100/200/300", m.Margin, m.Bound, m.Value)
		}
	})
}
