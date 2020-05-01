package base

import (
	"reflect"
	"testing"
)

func TestUnmarshalLinkNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *LinkNLRI
	}{
		{
			name:  "node nlri 1",
			input: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1A, 0x02, 0x00, 0x00, 0x04, 0x00, 0x01, 0x86, 0xA0, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
			expect: &LinkNLRI{
				ProtocolID: 2,
				Identifier: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				LocalNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						512: {
							Type:   512,
							Length: 4,
							Value:  []byte{0, 1, 134, 160},
						},
						513: {
							Type:   513,
							Length: 4,
							Value:  []byte{0, 0, 0, 0},
						},
						515: {
							Type:   515,
							Length: 6,
							Value:  []byte{0, 0, 0, 0, 0, 6},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLinkNLRI(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}

		})
	}
}
