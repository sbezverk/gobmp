package bgp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// buildAttr returns the wire form of a single path attribute: flags + type +
// length + value. Uses single-byte length (Extended Length flag clear).
func buildAttr(flags, attrType uint8, value []byte) []byte {
	out := []byte{flags, attrType, byte(len(value))}
	return append(out, value...)
}

// TestUnknownPathAttribute_Preserved verifies that an unrecognised path
// attribute (Type 99 here — IANA-unassigned) is captured in
// BaseAttributes.UnknownAttributes with its full flag byte and raw value
// instead of being silently dropped.
func TestUnknownPathAttribute_Preserved(t *testing.T) {
	value := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	// Optional + Transitive flags (0xC0) = "preserve and forward with Partial"
	// per RFC 4271 §5; we only need to assert the flag byte round-trips.
	raw := buildAttr(0xC0, 99, value)

	ba, err := UnmarshalBGPBaseAttributes(raw)
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes: %v", err)
	}
	if len(ba.UnknownAttributes) != 1 {
		t.Fatalf("len(UnknownAttributes) = %d, want 1", len(ba.UnknownAttributes))
	}
	ua := ba.UnknownAttributes[0]
	if ua.Type != 99 {
		t.Errorf("Type = %d, want 99", ua.Type)
	}
	if ua.Flags != 0xC0 {
		t.Errorf("Flags = %#x, want 0xC0 (Optional|Transitive)", ua.Flags)
	}
	if !bytes.Equal(ua.Value, value) {
		t.Errorf("Value = %#x, want %#x", ua.Value, value)
	}
}

// TestUnknownPathAttribute_KnownAndUnknownCoexist verifies that recognised
// attributes still parse normally when an unknown attribute is also present.
func TestUnknownPathAttribute_KnownAndUnknownCoexist(t *testing.T) {
	// Origin (Type 1) = igp (0)
	originAttr := buildAttr(0x40, 1, []byte{0x00})
	// Unknown Type 250
	unknownAttr := buildAttr(0xC0, 250, []byte{0x01, 0x02, 0x03})
	raw := append(originAttr, unknownAttr...)

	ba, err := UnmarshalBGPBaseAttributes(raw)
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes: %v", err)
	}
	if ba.Origin != "igp" {
		t.Errorf("Origin = %q, want \"igp\"", ba.Origin)
	}
	if len(ba.UnknownAttributes) != 1 || ba.UnknownAttributes[0].Type != 250 {
		t.Fatalf("UnknownAttributes = %+v, want one entry with Type=250", ba.UnknownAttributes)
	}
}

// TestUnknownPathAttribute_MultiplePreserveOrder verifies that multiple
// unknown attributes are captured in wire order.
func TestUnknownPathAttribute_MultiplePreserveOrder(t *testing.T) {
	raw := buildAttr(0xC0, 99, []byte{0xAA})
	raw = append(raw, buildAttr(0xC0, 100, []byte{0xBB})...)
	raw = append(raw, buildAttr(0x80, 101, []byte{0xCC})...)

	ba, err := UnmarshalBGPBaseAttributes(raw)
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes: %v", err)
	}
	if len(ba.UnknownAttributes) != 3 {
		t.Fatalf("len = %d, want 3", len(ba.UnknownAttributes))
	}
	wantTypes := []uint8{99, 100, 101}
	for i, want := range wantTypes {
		if ba.UnknownAttributes[i].Type != want {
			t.Errorf("UnknownAttributes[%d].Type = %d, want %d", i, ba.UnknownAttributes[i].Type, want)
		}
	}
	// Last one is Optional-but-not-Transitive (RFC 4271 §5 says quietly ignore +
	// not pass along). gobmp doesn't forward so we still surface it; assert
	// the original flag byte is preserved so consumers can apply their own policy.
	if ba.UnknownAttributes[2].Flags != 0x80 {
		t.Errorf("UnknownAttributes[2].Flags = %#x, want 0x80 (Optional non-Transitive)", ba.UnknownAttributes[2].Flags)
	}
}

// TestUnknownPathAttribute_EmptyValue verifies a zero-length unknown
// attribute is captured as present (length 0 Value) rather than dropped.
func TestUnknownPathAttribute_EmptyValue(t *testing.T) {
	raw := buildAttr(0xC0, 99, nil)
	ba, err := UnmarshalBGPBaseAttributes(raw)
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes: %v", err)
	}
	if len(ba.UnknownAttributes) != 1 {
		t.Fatalf("len = %d, want 1", len(ba.UnknownAttributes))
	}
	if len(ba.UnknownAttributes[0].Value) != 0 {
		t.Errorf("Value len = %d, want 0", len(ba.UnknownAttributes[0].Value))
	}
}

// TestUnknownPathAttribute_JSON locks the JSON tags and omitempty behaviour.
func TestUnknownPathAttribute_JSON(t *testing.T) {
	t.Run("present round-trips", func(t *testing.T) {
		original := &BaseAttributes{
			UnknownAttributes: []UnknownPathAttribute{
				{Type: 99, Flags: 0xC0, Value: []byte{0xDE, 0xAD}},
			},
		}
		b, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !strings.Contains(string(b), `"unknown_attributes":[`) {
			t.Errorf("missing unknown_attributes; got %s", b)
		}
		if !strings.Contains(string(b), `"type":99`) {
			t.Errorf("missing type field; got %s", b)
		}
		if !strings.Contains(string(b), `"flags":192`) {
			t.Errorf("missing flags field; got %s", b)
		}
		// json encodes []byte as base64; 0xDEAD → 3q0=
		if !strings.Contains(string(b), `"value":"3q0="`) {
			t.Errorf("missing/wrong value field; got %s", b)
		}

		recovered := &BaseAttributes{}
		if err := json.Unmarshal(b, recovered); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if len(recovered.UnknownAttributes) != 1 ||
			recovered.UnknownAttributes[0].Type != 99 ||
			recovered.UnknownAttributes[0].Flags != 0xC0 ||
			!bytes.Equal(recovered.UnknownAttributes[0].Value, []byte{0xDE, 0xAD}) {
			t.Errorf("round-trip lost; got %+v", recovered.UnknownAttributes)
		}
	})
	t.Run("absent omitempty fires", func(t *testing.T) {
		b, err := json.Marshal(&BaseAttributes{})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if strings.Contains(string(b), "unknown_attributes") {
			t.Errorf("unknown_attributes should be omitted; got %s", b)
		}
	})
}

// TestBaseAttributes_Equal_UnknownAttributes verifies BaseAttributes.Equal
// detects a difference in UnknownAttributes — without this, two updates
// that differ only in an unknown attribute would be deduped silently.
func TestBaseAttributes_Equal_UnknownAttributes(t *testing.T) {
	a := &BaseAttributes{
		UnknownAttributes: []UnknownPathAttribute{{Type: 99, Flags: 0xC0, Value: []byte{0x01}}},
	}
	b := &BaseAttributes{
		UnknownAttributes: []UnknownPathAttribute{{Type: 99, Flags: 0xC0, Value: []byte{0x02}}},
	}
	eq, diffs := a.Equal(b)
	if eq {
		t.Error("Equal returned true for different UnknownAttributes")
	}
	found := false
	for _, d := range diffs {
		if d == "unknown_attributes mismatch" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("missing unknown_attributes mismatch diff; got %v", diffs)
	}

	// Same UnknownAttributes → equal.
	c := &BaseAttributes{
		UnknownAttributes: []UnknownPathAttribute{{Type: 99, Flags: 0xC0, Value: []byte{0x01}}},
	}
	if eq, _ := a.Equal(c); !eq {
		t.Error("Equal returned false for identical UnknownAttributes")
	}

	// Both nil → equal.
	if eq, _ := (&BaseAttributes{}).Equal(&BaseAttributes{}); !eq {
		t.Error("Equal returned false for two empty BaseAttributes")
	}
}
