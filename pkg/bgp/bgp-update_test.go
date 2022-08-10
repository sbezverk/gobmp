package bgp

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

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
					BaseAttrHash: "3b87061fdf773278959113c6f010f24c",
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
