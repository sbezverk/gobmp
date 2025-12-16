package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

// uint32Ptr is a helper function to create a pointer to a uint32 value
func uint32Ptr(v uint32) *uint32 {
	return &v
}

// equalUint32Ptr compares two uint32 pointers for equality
func equalUint32Ptr(a, b *uint32) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func TestExtractColorEC(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *bgp.BaseAttributes
		expected *uint32
	}{
		{
			name: "Valid Color EC",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=100"},
			},
			expected: uint32Ptr(100),
		},
		{
			name: "No Color EC",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"rt=65000:100"},
			},
			expected: nil,
		},
		{
			name: "Multiple ECs with Color",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"rt=65000:100", "color=200", "ro=65000:200"},
			},
			expected: uint32Ptr(200),
		},
		{
			name:     "Nil BaseAttributes",
			attrs:    nil,
			expected: nil,
		},
		{
			name: "Nil ExtCommunityList",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: nil,
			},
			expected: nil,
		},
		{
			name: "Empty ExtCommunityList",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{},
			},
			expected: nil,
		},
		{
			name: "Color value zero",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=0"},
			},
			expected: uint32Ptr(0),
		},
		{
			name: "Color value max uint32",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=4294967295"},
			},
			expected: uint32Ptr(4294967295),
		},
		{
			name: "Invalid Color EC format - non-numeric",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=invalid"},
			},
			expected: nil,
		},
		{
			name: "Invalid Color EC format - negative",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=-100"},
			},
			expected: nil,
		},
		{
			name: "Invalid Color EC format - overflow uint32",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=4294967296"},
			},
			expected: nil,
		},
		{
			name: "Large color value within range",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=123456789"},
			},
			expected: uint32Ptr(123456789),
		},
		{
			name: "First Color EC used when multiple present",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=100", "color=200"},
			},
			expected: uint32Ptr(100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractColorEC(tt.attrs)
			if !equalUint32Ptr(result, tt.expected) {
				var resultVal, expectedVal string
				if result == nil {
					resultVal = "nil"
				} else {
					resultVal = string(rune(*result))
				}
				if tt.expected == nil {
					expectedVal = "nil"
				} else {
					expectedVal = string(rune(*tt.expected))
				}
				t.Errorf("extractColorEC() = %v, want %v", resultVal, expectedVal)
			}
		})
	}
}

func TestExtractColorEC_Integration(t *testing.T) {
	// Test with a realistic BGP BaseAttributes structure
	attrs := &bgp.BaseAttributes{
		Origin:           "igp",
		ASPath:           []uint32{65000, 65001},
		Nexthop:          "2001:db8::1",
		ExtCommunityList: []string{"rt=65000:100", "color=500", "ro=65000:200"},
	}

	color := extractColorEC(attrs)
	if color == nil {
		t.Fatalf("expected Color to be extracted, got nil")
	}
	if *color != 500 {
		t.Errorf("expected Color value 500, got %d", *color)
	}
}

func TestUnicastPrefix_ColorField(t *testing.T) {
	// Test UnicastPrefix struct with Color field
	prefix := &UnicastPrefix{
		Prefix:    "2001:db8::/32",
		PrefixLen: 32,
		Color:     uint32Ptr(100),
	}

	if prefix.Color == nil {
		t.Fatal("expected Color field to be set")
	}
	if *prefix.Color != 100 {
		t.Errorf("expected Color value 100, got %d", *prefix.Color)
	}

	// Test with nil Color
	prefix2 := &UnicastPrefix{
		Prefix:    "2001:db8:1::/48",
		PrefixLen: 48,
		Color:     nil,
	}

	if prefix2.Color != nil {
		t.Errorf("expected Color field to be nil, got %v", *prefix2.Color)
	}
}

func TestUnicastPrefix_Equal_WithColor(t *testing.T) {
	tests := []struct {
		name     string
		prefix1  *UnicastPrefix
		prefix2  *UnicastPrefix
		expected bool
	}{
		{
			name: "Equal prefixes with same Color",
			prefix1: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     uint32Ptr(100),
			},
			prefix2: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     uint32Ptr(100),
			},
			expected: true,
		},
		{
			name: "Different Color values",
			prefix1: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     uint32Ptr(100),
			},
			prefix2: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     uint32Ptr(200),
			},
			expected: false,
		},
		{
			name: "One Color nil, other set",
			prefix1: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     uint32Ptr(100),
			},
			prefix2: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     nil,
			},
			expected: false,
		},
		{
			name: "Both Color nil",
			prefix1: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     nil,
			},
			prefix2: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     nil,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal, diffs := tt.prefix1.Equal(tt.prefix2)
			if equal != tt.expected {
				t.Errorf("Equal() = %v, want %v. Diffs: %v", equal, tt.expected, diffs)
			}
		})
	}
}
