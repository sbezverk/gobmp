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
		{
			name:  "ipv6 with nlri",
			input: []byte{0x00, 0x00, 0x00, 0x75, 0x40, 0x01, 0x01, 0x02, 0x40, 0x02, 0x00, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0x80, 0x1D, 0x05, 0x04, 0x80, 0x00, 0x01, 0x00, 0x80, 0x0E, 0x55, 0x40, 0x04, 0x47, 0x10, 0x24, 0x09, 0x80, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x04, 0x00, 0x42, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5F, 0x50, 0x01, 0x00, 0x00, 0x1A, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x5F, 0x50, 0x02, 0x01, 0x00, 0x04, 0xD3, 0x88, 0xBF, 0xFF, 0x02, 0x03, 0x00, 0x06, 0x21, 0x11, 0x36, 0x19, 0x12, 0x36, 0x01, 0x09, 0x00, 0x11, 0x7F, 0x24, 0x09, 0x80, 0x1E, 0x00, 0xF0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCA},
			expect: &Update{
				WithdrawnRoutes:          make([]byte, 0),
				NLRI:                     make([]byte, 0),
				TotalPathAttributeLength: 117,
				BaseAttributes: &BaseAttributes{
					BaseAttrHash: "d40dcdbdb9d2f0ad6fef1efda93b5c49",
					LocalPref:    100,
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
						Attribute:          []byte{},
					},
					{
						AttributeTypeFlags: 128,
						AttributeType:      4,
						AttributeLength:    4,
						Attribute:          []byte{0, 0, 0, 0},
					},
					{
						AttributeTypeFlags: 64,
						AttributeType:      5,
						AttributeLength:    4,
						Attribute:          []byte{0, 0, 0, 100},
					},
					{
						AttributeTypeFlags: 128,
						AttributeType:      29,
						AttributeLength:    5,
						Attribute:          []byte{4, 128, 0, 1, 0},
					},
					{
						AttributeTypeFlags: 128,
						AttributeType:      14,
						AttributeLength:    85,
						Attribute:          []byte{64, 4, 71, 16, 36, 9, 128, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 4, 0, 66, 2, 0, 0, 0, 0, 0, 0, 95, 80, 1, 0, 0, 26, 2, 0, 0, 4, 0, 0, 95, 80, 2, 1, 0, 4, 211, 136, 191, 255, 2, 3, 0, 6, 33, 17, 54, 25, 18, 54, 1, 9, 0, 17, 127, 36, 9, 128, 30, 0, 240, 0, 1, 0, 0, 0, 0, 0, 0, 0, 202},
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

		})
	}
}
