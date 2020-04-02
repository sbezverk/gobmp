package base

import (
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
					Type:   256,
					Length: 12,
					SubTLV: []NodeDescriptorSubTLV{
						{
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
					Type:   256,
					Length: 12,
					SubTLV: []NodeDescriptorSubTLV{
						{
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
					Type:   256,
					Length: 8,
					SubTLV: []NodeDescriptorSubTLV{
						{
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
					Type:   256,
					Length: 8,
					SubTLV: []NodeDescriptorSubTLV{
						{
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
			got := tt.node.GetIGPRouterID()
			if strings.Compare(got, tt.expected) != 0 {
				t.Errorf("failed, expected %s got %s", tt.expected, got)
			}
		})
	}
}
