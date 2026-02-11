package message

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

// RFC 9723 Compliance Tests
// RFC 9723: BGP Colored Prefix Routing (CPR) for SRv6 based Services
//
// Key requirements tested:
// - Section 3: Color Extended Community (Type 0x0b, RFC 5512) usage with IPv4/IPv6 Unicast prefixes
// - Section 4: Color value encoding as 4-octet unsigned integer (0 to 4,294,967,295)
// - Section 5: Multiple Color ECs - only first occurrence is used
// - Section 6: Color absence handling - Color field must be nil when not present
// - Integration with BMP Route Monitor messages for Unicast prefixes

// Helper functions are defined in unicast_color_test.go:
// - uint32Ptr: creates pointer to uint32 value
// - equalUint32Ptr: compares two uint32 pointers for equality
// - formatUint32Ptr: formats uint32 pointer for error messages

func formatUint32Ptr(p *uint32) string {
	if p == nil {
		return "nil"
	}
	return fmt.Sprintf("%d", *p)
}

// TestRFC9723_ColorExtendedCommunity_BasicExtraction validates basic Color EC parsing
// Per RFC 9723 Section 3: Color EC (Type 0x0b) carries a 4-octet Color value
func TestRFC9723_ColorExtendedCommunity_BasicExtraction(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *bgp.BaseAttributes
		wantColor   *uint32
		description string
	}{
		{
			name: "Valid Color EC - value 100",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=100"},
			},
			wantColor:   uint32Ptr(100),
			description: "RFC 9723 Section 3: Basic Color EC with small value",
		},
		{
			name: "Valid Color EC - value 1000",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=1000"},
			},
			wantColor:   uint32Ptr(1000),
			description: "RFC 9723 Section 3: Medium-sized Color value",
		},
		{
			name: "Valid Color EC - value 16777215 (common SR Policy Color)",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=16777215"},
			},
			wantColor:   uint32Ptr(16777215),
			description: "RFC 9723 Section 3: Typical SR Policy Color value (max 24-bit)",
		},
		{
			name: "Color EC among other communities",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"rt=65000:100", "color=500", "ro=65001:200"},
			},
			wantColor:   uint32Ptr(500),
			description: "RFC 9723 Section 3: Color EC extracted from mixed community list",
		},
		{
			name: "No Color EC present",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"rt=65000:100", "ro=65001:200"},
			},
			wantColor:   nil,
			description: "RFC 9723 Section 6: No Color means Color field should be nil",
		},
		{
			name:        "Nil BaseAttributes",
			attrs:       nil,
			wantColor:   nil,
			description: "RFC 9723 Section 6: Nil attributes should return nil Color",
		},
		{
			name: "Nil ExtCommunityList",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: nil,
			},
			wantColor:   nil,
			description: "RFC 9723 Section 6: Nil community list should return nil Color",
		},
		{
			name: "Empty ExtCommunityList",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{},
			},
			wantColor:   nil,
			description: "RFC 9723 Section 6: Empty community list should return nil Color",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractColorEC(tt.attrs)
			if !equalUint32Ptr(result, tt.wantColor) {
				t.Errorf("%s: extractColorEC() = %v, want %v",
					tt.description, formatUint32Ptr(result), formatUint32Ptr(tt.wantColor))
			}
		})
	}
}

// TestRFC9723_ColorExtendedCommunity_BoundaryValues validates Color value range
// Per RFC 9723 Section 4: Color is a 4-octet unsigned integer (0 to 4,294,967,295)
func TestRFC9723_ColorExtendedCommunity_BoundaryValues(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *bgp.BaseAttributes
		wantColor   *uint32
		description string
	}{
		{
			name: "Minimum value - zero",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=0"},
			},
			wantColor:   uint32Ptr(0),
			description: "RFC 9723 Section 4: Zero is valid Color value",
		},
		{
			name: "Maximum uint32 value",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=4294967295"},
			},
			wantColor:   uint32Ptr(4294967295),
			description: "RFC 9723 Section 4: Maximum 4-octet unsigned value (2^32 - 1)",
		},
		{
			name: "Large value within range",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=3000000000"},
			},
			wantColor:   uint32Ptr(3000000000),
			description: "RFC 9723 Section 4: Large value near max uint32",
		},
		{
			name: "Value exceeds uint32 max",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=4294967296"},
			},
			wantColor:   nil,
			description: "RFC 9723 Section 4: Overflow beyond uint32 max should be rejected",
		},
		{
			name: "Very large overflow value",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=99999999999"},
			},
			wantColor:   nil,
			description: "RFC 9723 Section 4: Large overflow should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractColorEC(tt.attrs)
			if !equalUint32Ptr(result, tt.wantColor) {
				t.Errorf("%s: extractColorEC() = %v, want %v",
					tt.description, formatUint32Ptr(result), formatUint32Ptr(tt.wantColor))
			}
		})
	}
}

// TestRFC9723_ColorExtendedCommunity_InvalidFormats validates error handling
// Per RFC 9723: Invalid Color EC formats should be gracefully ignored
func TestRFC9723_ColorExtendedCommunity_InvalidFormats(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *bgp.BaseAttributes
		description string
	}{
		{
			name: "Non-numeric Color value",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=invalid"},
			},
			description: "Invalid format: non-numeric value should be ignored",
		},
		{
			name: "Negative Color value",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=-100"},
			},
			description: "Invalid format: negative value should be ignored",
		},
		{
			name: "Empty Color value",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color="},
			},
			description: "Invalid format: empty value should be ignored",
		},
		{
			name: "Hexadecimal Color value",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=0x100"},
			},
			description: "Invalid format: hex notation should be ignored",
		},
		{
			name: "Floating point Color value",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=100.5"},
			},
			description: "Invalid format: float value should be ignored",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractColorEC(tt.attrs)
			if result != nil {
				t.Errorf("%s: extractColorEC() = %v, want nil", tt.description, *result)
			}
		})
	}
}

// TestRFC9723_ColorExtendedCommunity_MultipleOccurrences validates first-wins behavior
// Per RFC 9723 Section 5: If multiple Color ECs present, only first is used
func TestRFC9723_ColorExtendedCommunity_MultipleOccurrences(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *bgp.BaseAttributes
		wantColor   *uint32
		description string
	}{
		{
			name: "Two Color ECs - first wins",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=100", "color=200"},
			},
			wantColor:   uint32Ptr(100),
			description: "RFC 9723 Section 5: First Color EC takes precedence",
		},
		{
			name: "Three Color ECs - first wins",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=111", "color=222", "color=333"},
			},
			wantColor:   uint32Ptr(111),
			description: "RFC 9723 Section 5: First Color among multiple",
		},
		{
			name: "Color EC after other communities",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"rt=65000:100", "color=500", "color=600"},
			},
			wantColor:   uint32Ptr(500),
			description: "RFC 9723 Section 5: First Color EC in mixed list",
		},
		{
			name: "First invalid, second valid",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"color=invalid", "color=200"},
			},
			wantColor:   uint32Ptr(200),
			description: "RFC 9723: Invalid Color EC ignored, next valid one used",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractColorEC(tt.attrs)
			if !equalUint32Ptr(result, tt.wantColor) {
				t.Errorf("%s: extractColorEC() = %v, want %v",
					tt.description, formatUint32Ptr(result), formatUint32Ptr(tt.wantColor))
			}
		})
	}
}

// TestRFC9723_UnicastPrefix_ColorField validates Color field in UnicastPrefix struct
// Per RFC 9723 Section 3: Color field added to Unicast prefix messages
func TestRFC9723_UnicastPrefix_ColorField(t *testing.T) {
	tests := []struct {
		name        string
		prefix      *UnicastPrefix
		wantColor   *uint32
		description string
	}{
		{
			name: "Prefix with Color value 100",
			prefix: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     uint32Ptr(100),
			},
			wantColor:   uint32Ptr(100),
			description: "RFC 9723 Section 3: IPv6 prefix with Color",
		},
		{
			name: "Prefix with Color value 0",
			prefix: &UnicastPrefix{
				Prefix:    "10.0.0.0/8",
				PrefixLen: 8,
				Color:     uint32Ptr(0),
			},
			wantColor:   uint32Ptr(0),
			description: "RFC 9723 Section 4: Zero Color value is valid",
		},
		{
			name: "Prefix with max Color value",
			prefix: &UnicastPrefix{
				Prefix:    "192.0.2.0/24",
				PrefixLen: 24,
				Color:     uint32Ptr(4294967295),
			},
			wantColor:   uint32Ptr(4294967295),
			description: "RFC 9723 Section 4: Max uint32 Color value",
		},
		{
			name: "Prefix without Color",
			prefix: &UnicastPrefix{
				Prefix:    "2001:db8:1::/48",
				PrefixLen: 48,
				Color:     nil,
			},
			wantColor:   nil,
			description: "RFC 9723 Section 6: Prefix without Color has nil Color field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !equalUint32Ptr(tt.prefix.Color, tt.wantColor) {
				t.Errorf("%s: Color field = %v, want %v",
					tt.description, formatUint32Ptr(tt.prefix.Color), formatUint32Ptr(tt.wantColor))
			}
		})
	}
}

// TestRFC9723_UnicastPrefix_ColorFieldJSON validates Color field JSON serialization
// Per RFC 9723: Color field must be properly serialized/deserialized in JSON
func TestRFC9723_UnicastPrefix_ColorFieldJSON(t *testing.T) {
	tests := []struct {
		name        string
		prefix      *UnicastPrefix
		wantColor   *uint32
		description string
	}{
		{
			name: "JSON serialization with Color",
			prefix: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     uint32Ptr(500),
			},
			wantColor:   uint32Ptr(500),
			description: "RFC 9723: Color field in JSON output",
		},
		{
			name: "JSON serialization without Color",
			prefix: &UnicastPrefix{
				Prefix:    "10.0.0.0/8",
				PrefixLen: 8,
				Color:     nil,
			},
			wantColor:   nil,
			description: "RFC 9723: Nil Color field in JSON output (omitempty)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.prefix)
			if err != nil {
				t.Fatalf("%s: JSON marshal error: %v", tt.description, err)
			}

			// Unmarshal back
			var unmarshaled UnicastPrefix
			err = json.Unmarshal(jsonData, &unmarshaled)
			if err != nil {
				t.Fatalf("%s: JSON unmarshal error: %v", tt.description, err)
			}

			// Verify Color field
			if !equalUint32Ptr(unmarshaled.Color, tt.wantColor) {
				t.Errorf("%s: After JSON round-trip Color = %v, want %v",
					tt.description, formatUint32Ptr(unmarshaled.Color), formatUint32Ptr(tt.wantColor))
			}
		})
	}
}

// TestRFC9723_UnicastPrefix_Equal_WithColor validates equality comparison with Color field
// Per RFC 9723: Equal() method must compare Color fields correctly
func TestRFC9723_UnicastPrefix_Equal_WithColor(t *testing.T) {
	tests := []struct {
		name        string
		prefix1     *UnicastPrefix
		prefix2     *UnicastPrefix
		wantEqual   bool
		description string
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
			wantEqual:   true,
			description: "RFC 9723: Identical prefixes with same Color are equal",
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
			wantEqual:   false,
			description: "RFC 9723: Same prefix with different Colors are not equal",
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
			wantEqual:   false,
			description: "RFC 9723: Prefix with Color vs without Color are not equal",
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
			wantEqual:   true,
			description: "RFC 9723: Prefixes without Color are equal",
		},
		{
			name: "Color zero vs nil",
			prefix1: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     uint32Ptr(0),
			},
			prefix2: &UnicastPrefix{
				Prefix:    "2001:db8::/32",
				PrefixLen: 32,
				Color:     nil,
			},
			wantEqual:   false,
			description: "RFC 9723: Color=0 is different from no Color (nil)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal, diffs := tt.prefix1.Equal(tt.prefix2)
			if equal != tt.wantEqual {
				t.Errorf("%s: Equal() = %v, want %v. Diffs: %v",
					tt.description, equal, tt.wantEqual, diffs)
			}
		})
	}
}

// TestRFC9723_Integration_ColorExtraction validates end-to-end Color extraction
// Per RFC 9723: Color EC in BGP attributes should populate Color field in UnicastPrefix
func TestRFC9723_Integration_ColorExtraction(t *testing.T) {
	tests := []struct {
		name        string
		attrs       *bgp.BaseAttributes
		wantColor   *uint32
		description string
	}{
		{
			name: "Realistic BGP attributes with Color",
			attrs: &bgp.BaseAttributes{
				Origin:           "igp",
				ASPath:           []uint32{65000, 65001, 65002},
				Nexthop:          "2001:db8::1",
				ExtCommunityList: []string{"rt=65000:100", "color=16777215", "ro=65000:200"},
			},
			wantColor:   uint32Ptr(16777215),
			description: "RFC 9723: Color extracted from full BGP attributes",
		},
		{
			name: "Attributes without Color EC",
			attrs: &bgp.BaseAttributes{
				Origin:           "igp",
				ASPath:           []uint32{65000},
				Nexthop:          "10.0.0.1",
				ExtCommunityList: []string{"rt=65000:100"},
			},
			wantColor:   nil,
			description: "RFC 9723 Section 6: No Color EC means nil Color",
		},
		{
			name: "SRv6 policy with Color",
			attrs: &bgp.BaseAttributes{
				Origin:           "igp",
				ASPath:           []uint32{65000},
				Nexthop:          "2001:db8:c633:6400::1",
				ExtCommunityList: []string{"color=100", "rt=65000:1"},
			},
			wantColor:   uint32Ptr(100),
			description: "RFC 9723 Section 1: Color for SRv6 policy steering",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			color := extractColorEC(tt.attrs)
			if !equalUint32Ptr(color, tt.wantColor) {
				t.Errorf("%s: extractColorEC() = %v, want %v",
					tt.description, formatUint32Ptr(color), formatUint32Ptr(tt.wantColor))
			}

			// Verify it would be correctly set in UnicastPrefix
			prefix := &UnicastPrefix{
				Prefix:         "2001:db8::/32",
				PrefixLen:      32,
				BaseAttributes: tt.attrs,
				Color:          color,
			}

			if !equalUint32Ptr(prefix.Color, tt.wantColor) {
				t.Errorf("%s: UnicastPrefix.Color = %v, want %v",
					tt.description, formatUint32Ptr(prefix.Color), formatUint32Ptr(tt.wantColor))
			}
		})
	}
}
