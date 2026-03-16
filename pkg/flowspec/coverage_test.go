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
	_, _, err := unmarshalSingleFlowspecNLRI([]byte{0xF0})
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
