package base

import (
	"reflect"
	"strings"
	"testing"
)

func TestGetIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		node     *NodeNLRI
		expected string
	}{
		{
			name: "8 bytes all zeros",
			node: &NodeNLRI{
				LocalNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						515: {
							Type:   515,
							Length: 8,
							Value:  []byte{0, 0, 0, 0, 0, 0, 0, 0},
						},
					},
				},
			},
			expected: "0000.0000.0000.0000",
		},
		{
			name: "8 bytes all zeros",
			node: &NodeNLRI{
				LocalNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						515: {
							Type:   515,
							Length: 8,
							Value:  []byte{0, 0, 0, 0, 0, 0, 0xf, 1},
						},
					},
				},
			},
			expected: "0000.0000.0000.1501",
		},
		{
			name: "4 bytes all zeros",
			node: &NodeNLRI{
				LocalNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						515: {
							Type:   515,
							Length: 4,
							Value:  []byte{0, 0, 0, 0},
						},
					},
				},
			},
			expected: "0.0.0.0",
		},
		{
			name: "4 bytes",
			node: &NodeNLRI{
				LocalNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						515: {
							Type:   515,
							Length: 4,
							Value:  []byte{0, 1, 0xff, 1},
						},
					},
				},
			},
			expected: "0.1.255.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.GetNodeIGPRouterID()
			if strings.Compare(got, tt.expected) != 0 {
				t.Errorf("failed, expected %s got %s", tt.expected, got)
			}
		})
	}
}

func TestUnmarshalNodeNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *NodeNLRI
	}{
		{
			name:  "node nlri 1",
			input: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1A, 0x02, 0x00, 0x00, 0x04, 0x00, 0x01, 0x86, 0xA0, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
			expect: &NodeNLRI{
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
			got, err := UnmarshalNodeNLRI(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}

		})
	}
}
