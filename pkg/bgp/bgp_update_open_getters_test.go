package bgp

import (
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// Update.GetAllAttributeID
// ---------------------------------------------------------------------------

func TestUpdate_GetAllAttributeID(t *testing.T) {
	tests := []struct {
		name    string
		attrs   []PathAttribute
		wantIDs []uint8
	}{
		{
			name:    "empty attributes",
			attrs:   nil,
			wantIDs: []uint8{},
		},
		{
			name: "single attribute",
			attrs: []PathAttribute{
				{AttributeType: 1},
			},
			wantIDs: []uint8{1},
		},
		{
			name: "multiple attributes",
			attrs: []PathAttribute{
				{AttributeType: 1},
				{AttributeType: 2},
				{AttributeType: 14},
			},
			wantIDs: []uint8{1, 2, 14},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := &Update{PathAttributes: tt.attrs}
			got := up.GetAllAttributeID()
			if len(got) != len(tt.wantIDs) {
				t.Fatalf("GetAllAttributeID() len=%d, want %d", len(got), len(tt.wantIDs))
			}
			for i, id := range tt.wantIDs {
				if got[i] != id {
					t.Errorf("GetAllAttributeID()[%d] = %d, want %d", i, got[i], id)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Update.GetBaseAttrHash
// ---------------------------------------------------------------------------

func TestUpdate_GetBaseAttrHash(t *testing.T) {
	up := &Update{
		PathAttributes: []PathAttribute{
			{AttributeType: 1, Attribute: []byte{0}},
		},
	}
	h1 := up.GetBaseAttrHash()
	if len(h1) != 32 { // MD5 hex = 32 chars
		t.Errorf("GetBaseAttrHash() length %d, want 32", len(h1))
	}
	// Same input → same hash
	h2 := up.GetBaseAttrHash()
	if h1 != h2 {
		t.Errorf("GetBaseAttrHash() not deterministic: %q != %q", h1, h2)
	}
	// Different attributes → different hash
	up2 := &Update{PathAttributes: []PathAttribute{{AttributeType: 2, Attribute: []byte{1}}}}
	if up.GetBaseAttrHash() == up2.GetBaseAttrHash() {
		t.Error("GetBaseAttrHash(): different attributes produced same hash")
	}
}

// ---------------------------------------------------------------------------
// Update.GetBGPLSAttribute
// ---------------------------------------------------------------------------

func TestUpdate_GetBGPLSAttribute_NotFound(t *testing.T) {
	up := &Update{
		PathAttributes: []PathAttribute{
			{AttributeType: 1, Attribute: []byte{}},
		},
	}
	_, err := up.GetBGPLSAttribute()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	notFound := &AttributeNotFoundError{}
	if !errors.As(err, &notFound) {
		t.Errorf("expected AttributeNotFoundError, got %T: %v", err, err)
	}
}

func TestUpdate_GetBGPLSAttribute_Success(t *testing.T) {
	// One BGP-LS TLV: Type=1024 (Node Flag Bits), Length=1, Value=0x80.
	bgplsAttr := []byte{0x04, 0x00, 0x00, 0x01, 0x80}
	up := &Update{
		PathAttributes: []PathAttribute{
			{AttributeType: 29, Attribute: bgplsAttr},
		},
	}
	ls, err := up.GetBGPLSAttribute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ls == nil {
		t.Fatal("expected non-nil NLRI")
	}
	if len(ls.LS) != 1 {
		t.Fatalf("expected 1 TLV, got %d", len(ls.LS))
	}
	if ls.LS[0].Type != 1024 {
		t.Errorf("TLV type = %d, want 1024", ls.LS[0].Type)
	}
}

func TestUpdate_GetBGPLSAttribute_MalformedReturnsError(t *testing.T) {
	// Truncated TLV header (1 byte; needs ≥ 4) → underlying parser must error.
	up := &Update{
		PathAttributes: []PathAttribute{
			{AttributeType: 29, Attribute: []byte{0xff}},
		},
	}
	_, err := up.GetBGPLSAttribute()
	if err == nil {
		t.Fatal("expected error from malformed BGP-LS attribute, got nil")
	}
}

// ---------------------------------------------------------------------------
// Update.GetAttrPrefixSID – not-found path
// ---------------------------------------------------------------------------

func TestUpdate_GetAttrPrefixSID_NotFound(t *testing.T) {
	up := &Update{
		PathAttributes: []PathAttribute{
			{AttributeType: 1, Attribute: []byte{}},
		},
	}
	_, err := up.GetAttrPrefixSID()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	notFound := &AttributeNotFoundError{}
	if !errors.As(err, &notFound) {
		t.Errorf("expected AttributeNotFoundError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Update.HasPrefixSID
// ---------------------------------------------------------------------------

func TestUpdate_HasPrefixSID(t *testing.T) {
	t.Run("no attr 40", func(t *testing.T) {
		up := &Update{PathAttributes: []PathAttribute{{AttributeType: 1}}}
		if up.HasPrefixSID() {
			t.Error("HasPrefixSID() = true, want false")
		}
	})
	t.Run("with attr 40", func(t *testing.T) {
		up := &Update{PathAttributes: []PathAttribute{{AttributeType: 40, Attribute: []byte{}}}}
		if !up.HasPrefixSID() {
			t.Error("HasPrefixSID() = false, want true")
		}
	})
}

// ---------------------------------------------------------------------------
// OpenMessage.GetCapabilities
// ---------------------------------------------------------------------------

func TestOpenMessage_GetCapabilities(t *testing.T) {
	caps := Capability{
		1: []*CapabilityData{{Description: "mp", Value: []byte{0, 1, 0, 1}}},
	}
	o := &OpenMessage{Capabilities: caps}
	got := o.GetCapabilities()
	if len(got) != 1 {
		t.Errorf("GetCapabilities() len=%d, want 1", len(got))
	}
	if _, ok := got[1]; !ok {
		t.Error("GetCapabilities() missing capability 1")
	}
}

// ---------------------------------------------------------------------------
// OpenMessage.IsMultiLabelCapable
// ---------------------------------------------------------------------------

func TestOpenMessage_IsMultiLabelCapable(t *testing.T) {
	t.Run("without capability 8", func(t *testing.T) {
		o := &OpenMessage{Capabilities: Capability{}}
		if o.IsMultiLabelCapable() {
			t.Error("IsMultiLabelCapable() = true, want false")
		}
	})
	t.Run("with capability 8", func(t *testing.T) {
		o := &OpenMessage{
			Capabilities: Capability{
				8: []*CapabilityData{{Description: "multi-label", Value: []byte{}}},
			},
		}
		if !o.IsMultiLabelCapable() {
			t.Error("IsMultiLabelCapable() = false, want true")
		}
	})
}
