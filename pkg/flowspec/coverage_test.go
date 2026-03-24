package flowspec

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestUnmarshalFlowspecNLRI_EmptyInput covers the len(b)==0 error path.
func TestUnmarshalFlowspecNLRI_EmptyInput(t *testing.T) {
	_, err := UnmarshalFlowspecNLRI([]byte{})
	if err == nil {
		t.Error("expected error for empty NLRI, got nil")
	}
}

// TestUnmarshalFlowspecNLRI_LengthExceedsData covers the length > available bytes error.
func TestUnmarshalFlowspecNLRI_LengthExceedsData(t *testing.T) {
	// Length byte says 10 but only 2 bytes of content follow.
	_, err := UnmarshalFlowspecNLRI([]byte{0x0A, 0x01, 0x00})
	if err == nil {
		t.Error("expected error for length exceeding data, got nil")
	}
}

// TestUnmarshalAllFlowspecNLRI_MultipleNLRIs validates parsing multiple concatenated
// flowspec NLRIs from a single MP_REACH_NLRI per RFC 8955 Section 4.
func TestUnmarshalAllFlowspecNLRI_MultipleNLRIs(t *testing.T) {
	// Two NLRIs concatenated:
	// NLRI 1: length=5, Type2 Source Prefix 10.0.7.0/24
	// NLRI 2: length=3, Type3 IP Protocol =47 (GRE)
	input := []byte{
		// NLRI 1: Source Prefix 10.0.7.0/24
		0x05,                   // Length: 5
		0x02,                   // Type 2: Source Prefix
		0x18,                   // Prefix length: 24
		0x0A, 0x00, 0x07,       // Prefix: 10.0.7
		// NLRI 2: IP Protocol = 47
		0x03,                   // Length: 3
		0x03,                   // Type 3: IP Protocol
		0x81,                   // Operator: EOL + EQ
		0x2F,                   // Value: 47 (GRE)
	}
	nlris, err := UnmarshalAllFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nlris) != 2 {
		t.Fatalf("expected 2 NLRIs, got %d", len(nlris))
	}
	// Verify first NLRI
	if nlris[0].Length != 5 {
		t.Errorf("NLRI[0] length: expected 5, got %d", nlris[0].Length)
	}
	if len(nlris[0].Spec) != 1 {
		t.Fatalf("NLRI[0] specs: expected 1, got %d", len(nlris[0].Spec))
	}
	ps, ok := nlris[0].Spec[0].(*PrefixSpec)
	if !ok {
		t.Fatal("NLRI[0] spec[0] is not PrefixSpec")
	}
	if ps.SpecType != 2 || ps.PrefixLength != 24 {
		t.Errorf("NLRI[0] PrefixSpec: type=%d prefixLen=%d", ps.SpecType, ps.PrefixLength)
	}
	// Verify second NLRI
	if nlris[1].Length != 3 {
		t.Errorf("NLRI[1] length: expected 3, got %d", nlris[1].Length)
	}
	if len(nlris[1].Spec) != 1 {
		t.Fatalf("NLRI[1] specs: expected 1, got %d", len(nlris[1].Spec))
	}
	gs, ok := nlris[1].Spec[0].(*GenericSpec)
	if !ok {
		t.Fatal("NLRI[1] spec[0] is not GenericSpec")
	}
	if gs.SpecType != 3 {
		t.Errorf("NLRI[1] GenericSpec type: expected 3, got %d", gs.SpecType)
	}
}

// TestUnmarshalAllFlowspecNLRI_EmptyInput returns nil slice for empty input (withdraw-all).
func TestUnmarshalAllFlowspecNLRI_EmptyInput(t *testing.T) {
	nlris, err := UnmarshalAllFlowspecNLRI([]byte{})
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if nlris != nil {
		t.Errorf("expected nil slice for empty input, got %d NLRIs", len(nlris))
	}
}

// TestUnmarshalAllFlowspecNLRI_SingleNLRI validates that single NLRI still parses correctly.
func TestUnmarshalAllFlowspecNLRI_SingleNLRI(t *testing.T) {
	input := []byte{
		0x05,                   // Length: 5
		0x02,                   // Type 2: Source Prefix
		0x18,                   // Prefix length: 24
		0x0A, 0x00, 0x07,       // Prefix: 10.0.7
	}
	nlris, err := UnmarshalAllFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nlris) != 1 {
		t.Fatalf("expected 1 NLRI, got %d", len(nlris))
	}
	if nlris[0].Length != 5 {
		t.Errorf("expected length 5, got %d", nlris[0].Length)
	}
}

// TestUnmarshalAllFlowspecNLRI_SixNLRIs validates parsing 6 NLRIs matching the Arista EOS pcap data.
func TestUnmarshalAllFlowspecNLRI_SixNLRIs(t *testing.T) {
	// Exact NLRI bytes from the pcap MP_REACH_NLRI (6 flowspec rules)
	input := []byte{
		// NLRI 1: len=17, dst 1.2.4.0/24, src 1.2.0.0/16, proto =6||=17, port =80
		0x11, 0x01, 0x18, 0x01, 0x02, 0x04, 0x02, 0x10,
		0x01, 0x02, 0x03, 0x01, 0x06, 0x81, 0x11, 0x04,
		0x81, 0x50,
		// NLRI 2: len=8, dst 1.2.6.0/24, fragment =IsF
		0x08, 0x01, 0x18, 0x01, 0x02, 0x06, 0x0c, 0x81, 0x02,
		// NLRI 3: len=32, dst 1.2.5.0/24, src 1.2.0.0/16, dstport, srcport, tcpflags, dscp
		0x20, 0x01, 0x18, 0x01, 0x02, 0x05, 0x02, 0x10,
		0x01, 0x02, 0x05, 0x11, 0x0c, 0x38, 0x12, 0x1f,
		0x90, 0xd4, 0x1f, 0x98, 0x06, 0x12, 0x03, 0xe8,
		0xd5, 0x07, 0xd0, 0x09, 0x81, 0x03, 0x0b, 0x81, 0x2a,
		// NLRI 4: len=4, src 1.2.0.0/16
		0x04, 0x02, 0x10, 0x01, 0x02,
		// NLRI 5: len=5, dst 1.2.3.0/24
		0x05, 0x01, 0x18, 0x01, 0x02, 0x03,
		// NLRI 6: len=15, dst 1.2.4.0/24, icmptype =15||=16, icmpcode =0||=1
		0x0f, 0x01, 0x18, 0x01, 0x02, 0x04, 0x07, 0x01,
		0x0f, 0x81, 0x10, 0x08, 0x01, 0x00, 0x81, 0x01,
	}
	nlris, err := UnmarshalAllFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nlris) != 6 {
		t.Fatalf("expected 6 NLRIs, got %d", len(nlris))
	}
	// Verify each NLRI has the expected length
	expectedLengths := []uint16{17, 8, 32, 4, 5, 15}
	for i, nlri := range nlris {
		if nlri.Length != expectedLengths[i] {
			t.Errorf("NLRI[%d] length: expected %d, got %d", i, expectedLengths[i], nlri.Length)
		}
		if nlri.SpecHash == "" {
			t.Errorf("NLRI[%d] has empty SpecHash", i)
		}
	}
	// Each NLRI should have a unique SpecHash
	hashes := make(map[string]bool)
	for i, nlri := range nlris {
		if hashes[nlri.SpecHash] {
			t.Errorf("NLRI[%d] has duplicate SpecHash %s", i, nlri.SpecHash)
		}
		hashes[nlri.SpecHash] = true
	}
}

// TestUnmarshalAllFlowspecNLRI_TruncatedSecondNLRI validates error on truncated data.
func TestUnmarshalAllFlowspecNLRI_TruncatedSecondNLRI(t *testing.T) {
	input := []byte{
		// Valid NLRI 1: len=3, Type3 IP Protocol =47
		0x03, 0x03, 0x81, 0x2F,
		// Truncated NLRI 2: length says 10 but only 1 byte follows
		0x0A, 0x01,
	}
	_, err := UnmarshalAllFlowspecNLRI(input)
	if err == nil {
		t.Error("expected error for truncated second NLRI, got nil")
	}
}

// TestUnmarshalFlowspecNLRI_BackwardCompatSingleNLRI ensures the original function
// still works for single-NLRI input after the refactor.
func TestUnmarshalFlowspecNLRI_BackwardCompatSingleNLRI(t *testing.T) {
	input := []byte{0x05, 0x02, 0x18, 0x0A, 0x00, 0x07}
	nlri, err := UnmarshalFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.Length != 5 {
		t.Errorf("expected length 5, got %d", nlri.Length)
	}
	if len(nlri.Spec) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(nlri.Spec))
	}
}

// TestUnmarshalSingleFlowspecNLRI_ExtendedLengthTooShort covers the 2-byte length guard.
func TestUnmarshalSingleFlowspecNLRI_ExtendedLengthTooShort(t *testing.T) {
	// First byte 0xF0 indicates 2-byte length, but only 1 byte provided
	_, _, err := unmarshalSingleFlowspecNLRI([]byte{0xF0}, false)
	if err == nil {
		t.Error("expected error for short extended length, got nil")
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

// TestUnmarshalOpVal_MissingEOL covers the error when OpVal sequence ends without EOL bit.
func TestUnmarshalOpVal_MissingEOL(t *testing.T) {
	// Type byte (0x03) + operator 0x01 (EQ bit, no EOL, length=1) + value 0x05
	// Operator 0x01: EOL=0, AND=0, length=1, LT=0, GT=0, EQ=1
	_, err := UnmarshalOpVal([]byte{0x03, 0x01, 0x05})
	if err == nil {
		t.Error("expected error for missing EOL bit, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "without EOL bit") {
		t.Errorf("unexpected error message: %v", err)
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
