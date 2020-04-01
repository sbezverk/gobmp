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
			name: "all zeros",
			node: &NodeNLRI{
				Identifier: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			},
			expected: "0000.0000.0000.0000",
		},
		{
			name: "1 number",
			node: &NodeNLRI{
				Identifier: []byte{0, 0, 0, 0, 0, 0, 0, 10},
			},
			expected: "0000.0000.0000.0010",
		},
		{
			name: "2 numbers",
			node: &NodeNLRI{
				Identifier: []byte{0, 0, 0, 0, 0, 0, 0xf, 10},
			},
			expected: "0000.0000.0000.1510",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.GetIdentifier()
			if strings.Compare(got, tt.expected) != 0 {
				t.Errorf("failed, expected %s got %s", tt.expected, got)
			}
		})
	}
}
