package prefixsid

import (
	"reflect"
	"testing"
)

func TestUnmarshalBGPAttrPrefixSID(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *PSid
	}{
		{
			name:  "mp unicast nlri 1",
			input: []byte{0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4},
			expect: &PSid{
				LabelIndex: &LabelIndexTLV{
					Type:       1,
					Length:     7,
					LabelIndex: 164,
				},
				OriginatorSRGB: nil,
			},
		},
		{
			name:  "prefix sid type 5",
			input: []byte{0x05, 0x00, 0x22, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
			expect: &PSid{
				LabelIndex: &LabelIndexTLV{
					Type:       1,
					Length:     7,
					LabelIndex: 164,
				},
				OriginatorSRGB: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBGPAttrPrefixSID(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected prefix sid %+v does not match the actual %+v", tt.expect, got)
			}
		})
	}
}
