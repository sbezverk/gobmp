package bgp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// buildAttr returns the wire form of a single path attribute: flags + type +
// length + value. Uses single-byte length (Extended Length flag clear).
// Panics if len(value) > 255; use buildAttrExtLen for larger values.
func buildAttr(flags, attrType uint8, value []byte) []byte {
	if len(value) > 255 {
		panic("buildAttr: value exceeds single-byte length; use buildAttrExtLen")
	}
	out := []byte{flags, attrType, byte(len(value))}
	return append(out, value...)
}

// buildAttrExtLen returns the wire form of a single path attribute with the
// Extended Length flag (0x10) forced on and a 2-byte length field, per
// RFC 4271 §4.3. Panics if len(value) > 65535.
func buildAttrExtLen(flags, attrType uint8, value []byte) []byte {
	if len(value) > 65535 {
		panic("buildAttrExtLen: value exceeds 2-byte length field")
	}
	flags |= 0x10
	out := []byte{flags, attrType, 0, 0}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(value)))
	return append(out, value...)
}

// TestUnknownPathAttribute_Preserved verifies that unrecognised path
// attributes are captured in BaseAttributes.UnknownAttributes with their full
// flag byte and raw value instead of being silently dropped, across the
// flag/length-encoding combinations gobmp can encounter on the wire.
func TestUnknownPathAttribute_Preserved(t *testing.T) {
	extLenValue := bytes.Repeat([]byte{0xAB}, 300)
	cases := []struct {
		name      string
		raw       []byte
		wantType  uint8
		wantFlags uint8
		wantValue []byte
	}{
		{
			name:      "optional transitive single byte length",
			raw:       buildAttr(0xC0, 99, []byte{0xDE, 0xAD, 0xBE, 0xEF}),
			wantType:  99,
			wantFlags: 0xC0,
			wantValue: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
		{
			name:      "optional non transitive single byte length",
			raw:       buildAttr(0x80, 100, []byte{0xAA, 0xBB}),
			wantType:  100,
			wantFlags: 0x80,
			wantValue: []byte{0xAA, 0xBB},
		},
		{
			name:      "extended length over 255 bytes",
			raw:       buildAttrExtLen(0xC0, 101, extLenValue),
			wantType:  101,
			wantFlags: 0xD0,
			wantValue: extLenValue,
		},
		{
			name:      "extended length zero value",
			raw:       buildAttrExtLen(0xC0, 102, nil),
			wantType:  102,
			wantFlags: 0xD0,
			wantValue: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ba, err := UnmarshalBGPBaseAttributes(tc.raw)
			if err != nil {
				t.Fatalf("UnmarshalBGPBaseAttributes: %v", err)
			}
			if len(ba.UnknownAttributes) != 1 {
				t.Fatalf("len(UnknownAttributes) = %d, want 1", len(ba.UnknownAttributes))
			}
			ua := ba.UnknownAttributes[0]
			if ua.Type != tc.wantType {
				t.Errorf("Type = %d, want %d", ua.Type, tc.wantType)
			}
			if ua.Flags != tc.wantFlags {
				t.Errorf("Flags = %#x, want %#x", ua.Flags, tc.wantFlags)
			}
			if !bytes.Equal(ua.Value, tc.wantValue) {
				t.Errorf("Value (len %d) = %x, want (len %d) %x", len(ua.Value), ua.Value, len(tc.wantValue), tc.wantValue)
			}
		})
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

	// nil slice vs empty (non-nil) slice → equal. A JSON-decoded
	// "unknown_attributes":[] must not be treated as different from a
	// parser-produced nil, which reflect.DeepEqual would have done.
	nilSide := &BaseAttributes{}
	emptySide := &BaseAttributes{UnknownAttributes: []UnknownPathAttribute{}}
	if eq, _ := nilSide.Equal(emptySide); !eq {
		t.Error("Equal returned false for nil vs empty UnknownAttributes")
	}

	// nil Value vs empty []byte{} Value → equal (both are zero-length).
	nilVal := &BaseAttributes{UnknownAttributes: []UnknownPathAttribute{{Type: 99, Flags: 0xC0, Value: nil}}}
	emptyVal := &BaseAttributes{UnknownAttributes: []UnknownPathAttribute{{Type: 99, Flags: 0xC0, Value: []byte{}}}}
	if eq, _ := nilVal.Equal(emptyVal); !eq {
		t.Error("Equal returned false for nil vs empty Value")
	}
}
