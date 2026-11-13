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

func TestSRPolicyJSONValidation(t *testing.T) {
	assertMarshalError := func(name string, marshal func() ([]byte, error)) {
		t.Helper()
		t.Run("Marshal/"+name, func(t *testing.T) {
			if _, err := marshal(); err == nil {
				t.Fatal("expected MarshalJSON error")
			}
		})
	}
	assertUnmarshalError := func(name string, value any, input string) {
		t.Helper()
		t.Run("Unmarshal/"+name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(input), value); err == nil {
				t.Fatalf("expected UnmarshalJSON error for %s", input)
			}
		})
	}

	var nilSID *SRv6SID
	assertMarshalError("SRv6SID/nil", nilSID.MarshalJSON)
	assertMarshalError("SRv6SID/short", func() ([]byte, error) {
		return (&SRv6SID{SID: make([]byte, 15)}).MarshalJSON()
	})
	assertUnmarshalError("SRv6SID/invalid-address", &SRv6SID{}, `{"srv6_sid":"not-an-ip"}`)
	assertUnmarshalError("SRv6SID/ipv4", &SRv6SID{}, `{"srv6_sid":"192.0.2.1"}`)

	var nilType3 *SRType3Descriptor
	assertMarshalError("SRType3/nil", nilType3.MarshalJSON)
	assertMarshalError("SRType3/short", func() ([]byte, error) {
		return (&SRType3Descriptor{IPv4NodeAddress: make([]byte, 3)}).MarshalJSON()
	})
	assertUnmarshalError("SRType3/invalid-address", &SRType3Descriptor{}, `{"ipv4_node_address":"not-an-ip"}`)
	assertUnmarshalError("SRType3/ipv6", &SRType3Descriptor{}, `{"ipv4_node_address":"2001:db8::1"}`)

	var nilType4 *SRType4Descriptor
	assertMarshalError("SRType4/nil", nilType4.MarshalJSON)
	assertMarshalError("SRType4/short", func() ([]byte, error) {
		return (&SRType4Descriptor{IPv6NodeAddress: make([]byte, 15)}).MarshalJSON()
	})
	assertUnmarshalError("SRType4/invalid-address", &SRType4Descriptor{}, `{"ipv6_node_address":"not-an-ip"}`)
	assertUnmarshalError("SRType4/ipv4", &SRType4Descriptor{}, `{"ipv6_node_address":"192.0.2.1"}`)

	var nilType5 *SRType5Descriptor
	assertMarshalError("SRType5/nil", nilType5.MarshalJSON)
	assertMarshalError("SRType5/short", func() ([]byte, error) {
		return (&SRType5Descriptor{LocalNodeIPv4: make([]byte, 3)}).MarshalJSON()
	})
	assertUnmarshalError("SRType5/invalid-address", &SRType5Descriptor{}, `{"local_node_ipv4":"not-an-ip"}`)
	assertUnmarshalError("SRType5/ipv6", &SRType5Descriptor{}, `{"local_node_ipv4":"2001:db8::1"}`)

	var nilType6 *SRType6Descriptor
	assertMarshalError("SRType6/nil", nilType6.MarshalJSON)
	assertMarshalError("SRType6/local-short", func() ([]byte, error) {
		return (&SRType6Descriptor{LocalInterfaceIPv4: make([]byte, 3), RemoteInterfaceIPv4: make([]byte, 4)}).MarshalJSON()
	})
	assertMarshalError("SRType6/remote-short", func() ([]byte, error) {
		return (&SRType6Descriptor{LocalInterfaceIPv4: make([]byte, 4), RemoteInterfaceIPv4: make([]byte, 3)}).MarshalJSON()
	})
	assertUnmarshalError("SRType6/local-invalid", &SRType6Descriptor{}, `{"local_interface_ipv4":"not-an-ip","remote_interface_ipv4":"192.0.2.2"}`)
	assertUnmarshalError("SRType6/local-ipv6", &SRType6Descriptor{}, `{"local_interface_ipv4":"2001:db8::1","remote_interface_ipv4":"192.0.2.2"}`)
	assertUnmarshalError("SRType6/remote-invalid", &SRType6Descriptor{}, `{"local_interface_ipv4":"192.0.2.1","remote_interface_ipv4":"not-an-ip"}`)
	assertUnmarshalError("SRType6/remote-ipv6", &SRType6Descriptor{}, `{"local_interface_ipv4":"192.0.2.1","remote_interface_ipv4":"2001:db8::2"}`)

	var nilType7 *SRType7Descriptor
	assertMarshalError("SRType7/nil", nilType7.MarshalJSON)
	assertMarshalError("SRType7/local-short", func() ([]byte, error) {
		return (&SRType7Descriptor{LocalNodeIPv6: make([]byte, 15), RemoteNodeIPv6: make([]byte, 16)}).MarshalJSON()
	})
	assertMarshalError("SRType7/remote-short", func() ([]byte, error) {
		return (&SRType7Descriptor{LocalNodeIPv6: make([]byte, 16), RemoteNodeIPv6: make([]byte, 15)}).MarshalJSON()
	})
	assertUnmarshalError("SRType7/local-invalid", &SRType7Descriptor{}, `{"local_node_ipv6":"not-an-ip","remote_node_ipv6":"2001:db8::2"}`)
	assertUnmarshalError("SRType7/local-ipv4", &SRType7Descriptor{}, `{"local_node_ipv6":"192.0.2.1","remote_node_ipv6":"2001:db8::2"}`)
	assertUnmarshalError("SRType7/remote-invalid", &SRType7Descriptor{}, `{"local_node_ipv6":"2001:db8::1","remote_node_ipv6":"not-an-ip"}`)
	assertUnmarshalError("SRType7/remote-ipv4", &SRType7Descriptor{}, `{"local_node_ipv6":"2001:db8::1","remote_node_ipv6":"192.0.2.2"}`)

	var nilType8 *SRType8Descriptor
	assertMarshalError("SRType8/nil", nilType8.MarshalJSON)
	assertMarshalError("SRType8/local-short", func() ([]byte, error) {
		return (&SRType8Descriptor{LocalInterfaceIPv6: make([]byte, 15), RemoteInterfaceIPv6: make([]byte, 16)}).MarshalJSON()
	})
	assertMarshalError("SRType8/remote-short", func() ([]byte, error) {
		return (&SRType8Descriptor{LocalInterfaceIPv6: make([]byte, 16), RemoteInterfaceIPv6: make([]byte, 15)}).MarshalJSON()
	})
	assertUnmarshalError("SRType8/local-invalid", &SRType8Descriptor{}, `{"local_interface_ipv6":"not-an-ip","remote_interface_ipv6":"2001:db8::2"}`)
	assertUnmarshalError("SRType8/local-ipv4", &SRType8Descriptor{}, `{"local_interface_ipv6":"192.0.2.1","remote_interface_ipv6":"2001:db8::2"}`)
	assertUnmarshalError("SRType8/remote-invalid", &SRType8Descriptor{}, `{"local_interface_ipv6":"2001:db8::1","remote_interface_ipv6":"not-an-ip"}`)
	assertUnmarshalError("SRType8/remote-ipv4", &SRType8Descriptor{}, `{"local_interface_ipv6":"2001:db8::1","remote_interface_ipv6":"192.0.2.2"}`)
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
		// SRSegmentType = 1206 = 0x04B6; Type 1 always carries its
		// one-byte Algorithm descriptor, even when the A flag is clear.
		b := []byte{
			0x04, 0xB6, 0x00, 0x05, // sub-TLV type=1206, length=5
			0x01, 0x00, 0x00, 0x00, 0x00, // SegmentType1, no flags, algorithm 0
		}
		got, err := UnmarshalSRSegmentListSubTLV(b)
		if err != nil {
			t.Fatalf("UnmarshalSRSegmentListSubTLV() error = %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("len(got) = %d, want 1", len(got))
		}
		if _, ok := got[0].(*SRSegment); !ok {
			t.Errorf("got[0] type = %T, want *SRSegment", got[0])
		}
		seg, ok := got[0].(*SRSegment)
		if !ok {
			t.Fatalf("value type = %T, want *SRSegment", got[0])
		}
		if seg.Segment != SegmentType1 {
			t.Errorf("SegmentType = %d, want %d", seg.Segment, SegmentType1)
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
		if len(got) != 1 {
			t.Fatalf("len(got) = %d, want 1", len(got))
		}
		m, ok := got[0].(*SRSegmentListMetric)
		if !ok {
			t.Fatalf("got[0] type = %T, want *SRSegmentListMetric", got[0])
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

	// P3-15 regression: multiple SRSegment sub-TLVs must all be preserved.
	// Before the fix, s[SRSegmentType] was overwritten on each iteration so
	// only the last segment survived.
	t.Run("MultipleSegments_AllPreserved", func(t *testing.T) {
		seg := []byte{
			0x04, 0xB6, 0x00, 0x05, // sub-TLV type=1206, length=5
			0x01, 0x00, 0x00, 0x00, 0x00, // SegmentType1, algorithm 0
		}
		// Three identical segments back-to-back.
		b := append(append(seg, seg...), seg...)
		got, err := UnmarshalSRSegmentListSubTLV(b)
		if err != nil {
			t.Fatalf("UnmarshalSRSegmentListSubTLV() error = %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("len(got) = %d, want 3 (all segments must be preserved)", len(got))
		}
		for i, v := range got {
			if _, ok := v.(*SRSegment); !ok {
				t.Errorf("got[%d] type = %T, want *SRSegment", i, v)
			}
		}
	})
}
