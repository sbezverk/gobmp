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
	// Length=3, Type1, PrefixLen=24 (needs 3 prefix bytes) but only 1 prefix byte (0x00) follows.
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

// TestUnmarshalIPv6FlowspecNLRI_Success validates a single IPv6 NLRI parse.
func TestUnmarshalIPv6FlowspecNLRI_Success(t *testing.T) {
	// 2001:db8::/32 destination prefix, offset=0
	input := []byte{
		0x07,                   // NLRI length: 7
		0x01,                   // Type 1: Destination Prefix
		0x20,                   // Prefix length: 32
		0x00,                   // Offset: 0
		0x20, 0x01, 0x0d, 0xb8, // 4 prefix bytes
	}
	nlri, err := UnmarshalIPv6FlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nlri.Spec) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(nlri.Spec))
	}
	ps, ok := nlri.Spec[0].(*PrefixSpec)
	if !ok {
		t.Fatalf("expected *PrefixSpec, got %T", nlri.Spec[0])
	}
	if ps.PrefixLength != 32 || ps.Offset != 0 {
		t.Errorf("got PrefixLength=%d Offset=%d, want 32/0", ps.PrefixLength, ps.Offset)
	}
}

// TestUnmarshalIPv6FlowspecNLRI_Empty covers the empty input error path.
func TestUnmarshalIPv6FlowspecNLRI_Empty(t *testing.T) {
	_, err := UnmarshalIPv6FlowspecNLRI([]byte{})
	if err == nil {
		t.Error("expected error for empty input, got nil")
	}
}

// TestUnmarshalIPv6FlowspecNLRI_TrailingBytes verifies the warning path when
// multiple NLRIs are passed to the single-parse function.
func TestUnmarshalIPv6FlowspecNLRI_TrailingBytes(t *testing.T) {
	// Two concatenated NLRIs; UnmarshalIPv6FlowspecNLRI should warn and return only first.
	nlri1 := []byte{0x07, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8}
	nlri2 := []byte{0x07, 0x02, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8}
	input := append(nlri1, nlri2...)
	nlri, err := UnmarshalIPv6FlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nlri.Spec) != 1 {
		t.Errorf("expected 1 spec from first NLRI, got %d", len(nlri.Spec))
	}
}

// TestUnmarshalFlowspecNLRI_TrailingBytes verifies the warning path for IPv4 multi-NLRI.
func TestUnmarshalFlowspecNLRI_TrailingBytes(t *testing.T) {
	// Two concatenated NLRIs: 10.0.0.0/8 and 192.168.0.0/16
	nlri1 := []byte{0x03, 0x01, 0x08, 0x0a}
	nlri2 := []byte{0x04, 0x01, 0x10, 0xc0, 0xa8}
	input := append(nlri1, nlri2...)
	nlri, err := UnmarshalFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nlri.Spec) != 1 {
		t.Errorf("expected 1 spec from first NLRI, got %d", len(nlri.Spec))
	}
}

// TestUnmarshalAllFlowspecNLRI_MultiNLRI verifies parsing multiple IPv4 NLRIs.
func TestUnmarshalAllFlowspecNLRI_MultiNLRI(t *testing.T) {
	// 10.0.0.0/8 followed by 192.168.0.0/16
	input := []byte{
		0x03, 0x01, 0x08, 0x0a,       // NLRI 1: 10.0.0.0/8
		0x04, 0x01, 0x10, 0xc0, 0xa8, // NLRI 2: 192.168.0.0/16
	}
	nlris, err := UnmarshalAllFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nlris) != 2 {
		t.Fatalf("expected 2 NLRIs, got %d", len(nlris))
	}
}

// TestUnmarshalAllIPv6FlowspecNLRI_MultiNLRI verifies parsing multiple IPv6 NLRIs.
func TestUnmarshalAllIPv6FlowspecNLRI_MultiNLRI(t *testing.T) {
	// Two /32 prefixes (destination then source) back-to-back.
	nlri1 := []byte{0x07, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8}
	nlri2 := []byte{0x07, 0x02, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb9}
	input := append(nlri1, nlri2...)
	nlris, err := UnmarshalAllIPv6FlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nlris) != 2 {
		t.Fatalf("expected 2 NLRIs, got %d", len(nlris))
	}
	if nlris[0].Spec[0].(*PrefixSpec).SpecType != 1 {
		t.Error("first NLRI should be Type 1")
	}
	if nlris[1].Spec[0].(*PrefixSpec).SpecType != 2 {
		t.Error("second NLRI should be Type 2")
	}
}

// TestUnmarshalAllFlowspecNLRI_Empty verifies empty input returns nil slice without error.
func TestUnmarshalAllFlowspecNLRI_Empty(t *testing.T) {
	nlris, err := UnmarshalAllFlowspecNLRI([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlris != nil {
		t.Errorf("expected nil slice for empty input, got %v", nlris)
	}
}

// TestUnmarshalAllFlowspecNLRI_ErrorPropagation verifies errors in subsequent NLRIs are surfaced.
func TestUnmarshalAllFlowspecNLRI_ErrorPropagation(t *testing.T) {
	// Valid first NLRI then a malformed second NLRI (length=10 but only 2 content bytes).
	input := []byte{
		0x03, 0x01, 0x08, 0x0a, // Valid: 10.0.0.0/8
		0x0A, 0x01, 0x08,       // Malformed: length=10 but only 2 content bytes
	}
	_, err := UnmarshalAllFlowspecNLRI(input)
	if err == nil {
		t.Error("expected error for malformed second NLRI, got nil")
	}
}

// TestExtendedNLRILength verifies the 2-byte extended NLRI length encoding path.
// The extended form is triggered when the first byte has 0xf in the high nibble.
func TestExtendedNLRILength(t *testing.T) {
	// First byte 0xf0: indicator nibble=0xf, upper length nibble=0x0.
	// Second byte 0x03: lower 8 bits of length → total length = 3.
	// Content: Type3 (IP Protocol), operator 0x80 (EOL + 1-byte value), value 0x06 (TCP).
	input := []byte{0xf0, 0x03, 0x03, 0x80, 0x06}
	nlri, err := UnmarshalFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error with extended length encoding: %v", err)
	}
	if len(nlri.Spec) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(nlri.Spec))
	}
}

// TestMakeIPv6PrefixSpec_OffsetExceedsLength verifies the offset>length error path.
func TestMakeIPv6PrefixSpec_OffsetExceedsLength(t *testing.T) {
	// Type=1, PrefixLength=16, Offset=32 (offset exceeds prefix length)
	_, _, err := makeIPv6PrefixSpec([]byte{0x01, 0x10, 0x20})
	if err == nil {
		t.Error("expected error when offset exceeds prefix length, got nil")
	}
}

// TestExtendedNLRILength_TooShort verifies the error when a 0xf0-prefix byte appears
// but there is no second byte to complete the 2-byte extended length field.
func TestExtendedNLRILength_TooShort(t *testing.T) {
	_, err := UnmarshalFlowspecNLRI([]byte{0xf0})
	if err == nil {
		t.Error("expected error for truncated extended NLRI length, got nil")
	}
}

// TestUnmarshalIPv6FlowspecNLRI_Error verifies that parse errors inside the single-parse
// IPv6 function are returned (covering the error return at the unmarshalSingleFlowspecNLRI call).
func TestUnmarshalIPv6FlowspecNLRI_Error(t *testing.T) {
	// NLRI length=2, content=[Type1, PrefixLen=32] — too short for IPv6 prefix (needs offset byte too)
	_, err := UnmarshalIPv6FlowspecNLRI([]byte{0x02, 0x01, 0x20})
	if err == nil {
		t.Error("expected error for truncated IPv6 prefix spec, got nil")
	}
}

// TestSpecHash_AFINamespace verifies that IPv4 and IPv6 NLRIs with identical Type3 specs
// produce different SpecHash values after the AFI-namespacing fix.
func TestSpecHash_AFINamespace(t *testing.T) {
	// Type 3 (IP Protocol = TCP): Type(1) + Operator(1 byte EOL+EQ) + Value(1 byte = 6)
	spec := []byte{0x03, 0x81, 0x06}
	ipv4Input := append([]byte{byte(len(spec))}, spec...)
	ipv6Input := append([]byte{byte(len(spec))}, spec...)

	ipv4NLRIs, err := UnmarshalAllFlowspecNLRI(ipv4Input)
	if err != nil {
		t.Fatalf("IPv4 parse error: %v", err)
	}
	ipv6NLRIs, err := UnmarshalAllIPv6FlowspecNLRI(ipv6Input)
	if err != nil {
		t.Fatalf("IPv6 parse error: %v", err)
	}
	if ipv4NLRIs[0].SpecHash == ipv6NLRIs[0].SpecHash {
		t.Errorf("SpecHash collision: IPv4 and IPv6 produced identical hash %s", ipv4NLRIs[0].SpecHash)
	}
}
