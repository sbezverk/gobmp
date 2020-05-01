package base

import (
	"reflect"
	"testing"
)

func TestUnmarshalPrefixNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *PrefixNLRI
		ipv4   bool
	}{
		{
			name:  "prefix nlri 1",
			input: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0x01, 0x07, 0x00, 0x02, 0x00, 0x02, 0x01, 0x09, 0x00, 0x10, 0x78, 0x00, 0x90, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expect: &PrefixNLRI{
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
							Value:  []byte{0, 0, 0, 0, 0, 147},
						},
					},
				},
				Prefix: &PrefixDescriptor{
					PrefixTLV: map[uint16]TLV{
						263: {
							Type:   263,
							Length: 2,
							Value:  []byte{0, 2},
						},
						265: {
							Type:   265,
							Length: 16,
							Value:  []byte{120, 0, 144, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
						},
					},
				},
				LocalNodeHash: "ae68e174edda04ddf80610d2bec9c522",
				IsIPv4:        false,
			},
			ipv4: false,
		},
		{
			name:  "prefix nlri 2",
			input: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0x01, 0x09, 0x00, 0x04, 0x18, 0x09, 0x00, 0xcb},
			expect: &PrefixNLRI{
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
							Value:  []byte{0, 0, 0, 0, 0, 147},
						},
					},
				},
				Prefix: &PrefixDescriptor{
					PrefixTLV: map[uint16]TLV{
						265: {
							Type:   265,
							Length: 4,
							Value:  []byte{24, 9, 0, 203},
						},
					},
				},
				LocalNodeHash: "ae68e174edda04ddf80610d2bec9c522",
				IsIPv4:        true,
			},
			ipv4: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalPrefixNLRI(tt.input, tt.ipv4)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			//			fmt.Printf("got: \n%+v\n expect:\n%+v\n", *got, *tt.expect)
			//			fmt.Printf("got local: \n%+v\n expect local:\n%+v\n", *got.LocalNode, *tt.expect.LocalNode)
			//			fmt.Printf("got prefix: \n%+v\n expect prefix:\n%+v\n", *got.Prefix, *tt.expect.Prefix)
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}

		})
	}
}
