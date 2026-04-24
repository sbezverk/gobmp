package bgp

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

// TestUnmarshalBGPUpdate_AS4Hint verifies the optional as4 hint forces
// AS_PATH to parse as 2-byte or 4-byte ASNs, overriding the heuristic.
func TestUnmarshalBGPUpdate_AS4Hint(t *testing.T) {
	// 2-byte AS_PATH: segType=0x02 (AS_SEQUENCE), segLen=0x02, ASNs [64512, 64513].
	// Attr: flags=0x40, type=2 (AS_PATH), len=6, segment (6 bytes).
	as2Attr := []byte{0x40, 0x02, 0x06, 0x02, 0x02, 0xFC, 0x00, 0xFC, 0x01}
	originAttr := []byte{0x40, 0x01, 0x01, 0x00} // Origin=IGP
	attrs2 := append(append([]byte{}, originAttr...), as2Attr...)
	update2 := append([]byte{0x00, 0x00, 0x00, byte(len(attrs2))}, attrs2...)

	// 4-byte AS_PATH: segType=0x02, segLen=0x02, ASNs [131072, 131073].
	// Attr: flags=0x40, type=2, len=10, segment (10 bytes).
	as4Attr := []byte{0x40, 0x02, 0x0A, 0x02, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01}
	attrs4 := append(append([]byte{}, originAttr...), as4Attr...)
	update4 := append([]byte{0x00, 0x00, 0x00, byte(len(attrs4))}, attrs4...)

	t.Run("hint=false forces 2-byte parsing", func(t *testing.T) {
		u, err := UnmarshalBGPUpdateWithAS4Hint(update2, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []uint32{64512, 64513}
		if !reflect.DeepEqual(u.BaseAttributes.ASPath, want) {
			t.Errorf("ASPath=%v, want %v", u.BaseAttributes.ASPath, want)
		}
	})

	t.Run("hint=true forces 4-byte parsing", func(t *testing.T) {
		u, err := UnmarshalBGPUpdateWithAS4Hint(update4, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []uint32{131072, 131073}
		if !reflect.DeepEqual(u.BaseAttributes.ASPath, want) {
			t.Errorf("ASPath=%v, want %v", u.BaseAttributes.ASPath, want)
		}
	})

	t.Run("hint=true on 2-byte payload fails", func(t *testing.T) {
		// 2-byte payload under 4-byte interpretation needs 8 bytes per segment
		// but only has 4 -> truncation error.
		_, err := UnmarshalBGPUpdateWithAS4Hint(update2, true)
		if err == nil {
			t.Fatal("expected truncation error under 4-byte hint, got nil")
		}
	})
}

func TestUnmarshalBGPUpdate(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *Update
	}{
		{
			name:  "issue_173",
			input: []byte{0x00, 0x00, 0x00, 0x2C, 0x40, 0x01, 0x01, 0x02, 0x40, 0x02, 0x0A, 0x02, 0x02, 0x00, 0x00, 0xFD, 0xE9, 0x00, 0x00, 0xFD, 0xEB, 0x80, 0x0E, 0x18, 0x00, 0x02, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x0A, 0x98, 0xB7, 0x0B, 0x00, 0x10, 0x20, 0x01},
			expect: &Update{
				WithdrawnRoutes:          make([]byte, 0),
				NLRI:                     make([]byte, 0),
				TotalPathAttributeLength: 44,
				BaseAttributes: &BaseAttributes{
					BaseAttrHash: "8681ce86ce93dc0060f7582ae21cc6a1",
					ASPath:       []uint32{65001, 65003},
					ASPathCount:  2,
					Origin:       "incomplete",
				},
				PathAttributes: []PathAttribute{
					{
						AttributeTypeFlags: 64,
						AttributeType:      1,
						AttributeLength:    1,
						Attribute:          []byte{2},
					},
					{
						AttributeTypeFlags: 64,
						AttributeType:      2,
						AttributeLength:    10,
						Attribute:          []byte{2, 2, 0, 0, 253, 233, 0, 0, 253, 235},
					},
					{
						AttributeTypeFlags: 128,
						AttributeType:      14,
						AttributeLength:    24,
						Attribute:          []byte{0, 2, 1, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 152, 183, 11, 0, 16, 32, 1},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := UnmarshalBGPUpdate(tt.input)
			if err != nil {
				t.Fatalf("failed to unmarshal BGP Update with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, actual) {
				t.Logf("differences: %+v", deep.Equal(tt.expect, actual))
				t.Fatal("the expected object does not match the actual")
			}
			// Validate if Update carries valid attributes and values
			nlri, index := actual.GetNLRIType()
			if nlri != MP_REACH_NLRI {
				t.Fatal("Update carries unexpected type")
			}
			if index != 2 {
				t.Fatal("no MP_REACH attribute at expected position on Path Attributes array")
			}
		})
	}
}
