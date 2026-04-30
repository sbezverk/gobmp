package bgp

import (
	"testing"
)

// TestUnmarshalBaseAttrs_BGPLSAttributeMalformed pins RFC 9552 §5.3 / RFC 7606 §3
// 'Attribute Discard' behavior for path attribute 29 (BGP-LS Attribute):
// when the TLV stream is malformed, base-attribute parsing must NOT abort the
// whole UPDATE — other attributes (here: Origin = 1) must still be populated.
func TestUnmarshalBaseAttrs_BGPLSAttributeMalformed(t *testing.T) {
	attrs := []PathAttribute{
		{AttributeType: 1, Attribute: []byte{0x01}}, // Origin = EGP
		// Attr 29 with a truncated TLV header (1 byte; needs ≥ 4 for type+length)
		{AttributeType: 29, Attribute: []byte{0xff}},
	}

	ba, err := unmarshalBaseAttrsFromSlice(attrs, nil)
	if err != nil {
		t.Fatalf("unmarshalBaseAttrsFromSlice() unexpected error: %v", err)
	}
	if ba == nil {
		t.Fatal("unmarshalBaseAttrsFromSlice() returned nil BaseAttributes")
	}
	// Origin parsing must have proceeded past the malformed BGP-LS attribute.
	if ba.Origin == "" {
		t.Error("Origin not populated; BGP-LS malformed attribute must not abort UPDATE parsing per RFC 7606 §3 (Attribute Discard)")
	}
}

// TestUnmarshalBaseAttrs_BGPLSAttributeWellFormed verifies the happy path: a
// well-formed BGP-LS Attribute (TLV header 4B + payload) does not error and
// other attributes are populated normally.
func TestUnmarshalBaseAttrs_BGPLSAttributeWellFormed(t *testing.T) {
	// One BGP-LS TLV: Type=1024 (Node Flag Bits), Length=1, Value=0x80.
	bgplsAttr := []byte{0x04, 0x00, 0x00, 0x01, 0x80}

	attrs := []PathAttribute{
		{AttributeType: 1, Attribute: []byte{0x00}}, // Origin = IGP
		{AttributeType: 29, Attribute: bgplsAttr},
	}

	ba, err := unmarshalBaseAttrsFromSlice(attrs, nil)
	if err != nil {
		t.Fatalf("unmarshalBaseAttrsFromSlice() unexpected error: %v", err)
	}
	if ba.Origin == "" {
		t.Error("Origin not populated for well-formed BGP-LS attribute")
	}
}
