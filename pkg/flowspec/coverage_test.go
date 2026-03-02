package flowspec

import (
	"encoding/json"
	"testing"
)

// TestUnmarshalFlowspecNLRI_EmptyInput covers the len(b)==0 error path.
func TestUnmarshalFlowspecNLRI_EmptyInput(t *testing.T) {
	_, err := UnmarshalFlowspecNLRI([]byte{})
	if err == nil {
		t.Error("expected error for empty NLRI, got nil")
	}
}

// TestUnmarshalFlowspecNLRI_LengthMismatch covers the encoded-length != slice-length error.
func TestUnmarshalFlowspecNLRI_LengthMismatch(t *testing.T) {
	// Length byte says 10 but only 2 bytes of content follow.
	_, err := UnmarshalFlowspecNLRI([]byte{0x0A, 0x01, 0x00})
	if err == nil {
		t.Error("expected error for length mismatch, got nil")
	}
}

// TestUnmarshalFlowspecNLRI_TruncatedPrefix covers the makePrefixSpec error path
// within UnmarshalFlowspecNLRI when a prefix NLRI has insufficient bytes.
func TestUnmarshalFlowspecNLRI_TruncatedPrefix(t *testing.T) {
	// Length=3, Type1, PrefixLen=24 (needs 3 prefix bytes) but none follow.
	_, err := UnmarshalFlowspecNLRI([]byte{0x03, 0x01, 0x18, 0x00})
	if err == nil {
		t.Error("expected error for truncated prefix bytes, got nil")
	}
}

// TestUnmarshalFlowspecNLRI_TruncatedOpVal covers the UnmarshalOpVal error path
// within UnmarshalFlowspecNLRI when an operator declares more value bytes than are available.
func TestUnmarshalFlowspecNLRI_TruncatedOpVal(t *testing.T) {
	// Length=2, Type3 (IP Protocol), operator 0x10 (length=2) but 0 value bytes.
	_, err := UnmarshalFlowspecNLRI([]byte{0x02, 0x03, 0x10})
	if err == nil {
		t.Error("expected error for truncated operator value, got nil")
	}
}

// TestMakePrefixSpec_TooShort covers the len(b)<2 guard in makePrefixSpec.
func TestMakePrefixSpec_TooShort(t *testing.T) {
	_, _, err := makePrefixSpec([]byte{0x01})
	if err == nil {
		t.Error("expected error for 1-byte input to makePrefixSpec, got nil")
	}
}

// TestMakePrefixSpec_TruncatedPrefix covers the p+l>len(b) guard in makePrefixSpec.
func TestMakePrefixSpec_TruncatedPrefix(t *testing.T) {
	// Type=1, PrefixLen=24 (needs 3 bytes) but 0 prefix bytes follow.
	_, _, err := makePrefixSpec([]byte{0x01, 0x18})
	if err == nil {
		t.Error("expected error for truncated prefix bytes in makePrefixSpec, got nil")
	}
}

// TestUnmarshalOpVal_TruncatedValue covers the "not enough bytes" error in UnmarshalOpVal.
func TestUnmarshalOpVal_TruncatedValue(t *testing.T) {
	// Type byte (skipped) + operator 0x10 (length=2) + 0 value bytes.
	_, err := UnmarshalOpVal([]byte{0x03, 0x10})
	if err == nil {
		t.Error("expected error for truncated OpVal value bytes, got nil")
	}
}

// TestOperator_UnmarshalJSON_BadJSON covers the error path in Operator.UnmarshalJSON.
func TestOperator_UnmarshalJSON_BadJSON(t *testing.T) {
	o := &Operator{}
	if err := o.UnmarshalJSON([]byte(`{invalid}`)); err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestPrefixSpec_UnmarshalJSON_BadJSON covers the error path in PrefixSpec.UnmarshalJSON.
func TestPrefixSpec_UnmarshalJSON_BadJSON(t *testing.T) {
	p := &PrefixSpec{}
	if err := p.UnmarshalJSON([]byte(`{invalid}`)); err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestOpVal_UnmarshalJSON_BadJSON covers the error path in OpVal.UnmarshalJSON.
func TestOpVal_UnmarshalJSON_BadJSON(t *testing.T) {
	o := &OpVal{}
	if err := o.UnmarshalJSON([]byte(`{invalid}`)); err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestGenericSpec_UnmarshalJSON_BadJSON covers the error path in GenericSpec.UnmarshalJSON.
func TestGenericSpec_UnmarshalJSON_BadJSON(t *testing.T) {
	g := &GenericSpec{}
	if err := g.UnmarshalJSON([]byte(`{invalid}`)); err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestNLRI_SpecHashStability verifies the spec hash is deterministic.
func TestNLRI_SpecHashStability(t *testing.T) {
	input := []byte{
		0x06,             // Length: 6
		0x01,             // Type1: Dest Prefix
		0x20,             // /32
		192, 168, 1, 100, // 192.168.1.100
	}
	nlri1, err := UnmarshalFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("first unmarshal: %v", err)
	}
	nlri2, err := UnmarshalFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("second unmarshal: %v", err)
	}
	if nlri1.SpecHash != nlri2.SpecHash {
		t.Errorf("SpecHash not stable: %s != %s", nlri1.SpecHash, nlri2.SpecHash)
	}
}

// TestOperator_MarshalJSON verifies MarshalJSON produces valid JSON with correct keys.
func TestOperator_MarshalJSON(t *testing.T) {
	orig := &Operator{EOLBit: true, Length: 2, GTBit: true, EQBit: true}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if _, ok := m["end_of_list_bit"]; !ok {
		t.Error("expected key 'end_of_list_bit' in JSON output")
	}
}

// TestPrefixSpec_MarshalJSON verifies PrefixSpec.MarshalJSON produces valid JSON.
func TestPrefixSpec_MarshalJSON(t *testing.T) {
	ps := &PrefixSpec{SpecType: 1, PrefixLength: 24, Prefix: []byte{10, 0, 1}}
	b, err := ps.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
}

// TestOpVal_MarshalJSON verifies OpVal.MarshalJSON produces valid JSON.
func TestOpVal_MarshalJSON(t *testing.T) {
	ov := &OpVal{Op: &Operator{EOLBit: true, Length: 1, EQBit: true}, Val: []byte{0x06}}
	b, err := ov.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
}
