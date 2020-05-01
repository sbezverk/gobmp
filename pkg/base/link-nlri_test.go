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
			name:  "link nlri 1",
			input: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x91, 0x01, 0x01, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0x01, 0x03, 0x00, 0x04, 0x09, 0x00, 0x67, 0x01, 0x01, 0x04, 0x00, 0x04, 0x09, 0x00, 0x67, 0x02},
			expect: &LinkNLRI{
				ProtocolID: 2,
				Identifier: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				LocalNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						512: {
							Type:   512,
							Length: 4,
							Value:  []byte{0, 0, 19, 206},
						},
						513: {
							Type:   513,
							Length: 4,
							Value:  []byte{0, 0, 0, 0},
						},
						515: {
							Type:   515,
							Length: 6,
							Value:  []byte{0, 0, 0, 0, 0, 145},
						},
					},
				},
				RemoteNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						512: {
							Type:   512,
							Length: 4,
							Value:  []byte{0, 0, 19, 206},
						},
						513: {
							Type:   513,
							Length: 4,
							Value:  []byte{0, 0, 0, 0},
						},
						515: {
							Type:   515,
							Length: 6,
							Value:  []byte{0, 0, 0, 0, 0, 147},
						},
					},
				},
				Link: &LinkDescriptor{
					LinkTLV: map[uint16]TLV{
						259: {
							Type:   259,
							Length: 4,
							Value:  []byte{9, 0, 103, 1},
						},
						260: {
							Type:   260,
							Length: 4,
							Value:  []byte{9, 0, 103, 2},
						},
					},
				},
				LocalNodeHash:  "ae68e174edda04ddf80610d2bec9c522",
				RemoteNodeHash: "b0ca71813b4508962008be1bb3b73d8d",
				LinkHash:       "65a0b6cef01433f331b40f4102fb5f73",
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
