package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

// stringPtr is a helper function to create a pointer to a string value
func stringPtr(s string) *string {
	return &s
}

// equalStringPtr compares two string pointers for equality
func equalStringPtr(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func TestExtractOriginValidation(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *bgp.BaseAttributes
		expected *string
	}{
		{
			name: "Valid State",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"ov-state=valid"},
			},
			expected: stringPtr("valid"),
		},
		{
			name: "Not Found State",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"ov-state=not-found"},
			},
			expected: stringPtr("not-found"),
		},
		{
			name: "Invalid State",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"ov-state=invalid"},
			},
			expected: stringPtr("invalid"),
		},
		{
			name: "No OV State EC",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"rt=65000:100"},
			},
			expected: nil,
		},
		{
			name: "Multiple ECs with OV State",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"rt=65000:100", "ov-state=valid", "ro=65000:200"},
			},
			expected: stringPtr("valid"),
		},
		{
			name: "Multiple ECs without OV State",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"rt=65000:100", "color=100", "ro=65000:200"},
			},
			expected: nil,
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
			name: "Unknown State Value",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"ov-state=unknown=3"},
			},
			expected: nil, // Only valid, not-found, invalid accepted
		},
		{
			name: "Malformed State",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"ov-state=malformed"},
			},
			expected: nil,
		},
		{
			name: "First Valid State Used",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{"ov-state=valid", "ov-state=invalid"},
			},
			expected: stringPtr("valid"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractOriginValidation(tt.attrs)
			if !equalStringPtr(result, tt.expected) {
				var resultVal, expectedVal string
				if result == nil {
					resultVal = "nil"
				} else {
					resultVal = *result
				}
				if tt.expected == nil {
					expectedVal = "nil"
				} else {
					expectedVal = *tt.expected
				}
				t.Errorf("extractOriginValidation() = %q, want %q", resultVal, expectedVal)
			}
		})
	}
}

func TestExtractOriginValidation_Integration(t *testing.T) {
	// Test with realistic BGP BaseAttributes structure
	attrs := &bgp.BaseAttributes{
		Origin:           "igp",
		ASPath:           []uint32{65000, 65001},
		Nexthop:          "2001:db8::1",
		ExtCommunityList: []string{"rt=65000:100", "ov-state=valid", "color=500"},
	}

	ovState := extractOriginValidation(attrs)
	if ovState == nil {
		t.Fatalf("expected Origin Validation state to be extracted, got nil")
	}
	if *ovState != "valid" {
		t.Errorf("expected Origin Validation state 'valid', got %q", *ovState)
	}
}

func TestUnicastPrefix_OriginValidationField(t *testing.T) {
	// Test UnicastPrefix struct with OriginValidation field
	prefix := &UnicastPrefix{
		Prefix:           "2001:db8::/32",
		PrefixLen:        32,
		OriginValidation: stringPtr("valid"),
	}

	if prefix.OriginValidation == nil {
		t.Fatal("expected OriginValidation field to be set")
	}
	if *prefix.OriginValidation != "valid" {
		t.Errorf("expected OriginValidation 'valid', got %q", *prefix.OriginValidation)
	}

	// Test with nil OriginValidation
	prefix2 := &UnicastPrefix{
		Prefix:           "2001:db8:1::/48",
		PrefixLen:        48,
		OriginValidation: nil,
	}

	if prefix2.OriginValidation != nil {
		t.Errorf("expected OriginValidation field to be nil, got %q", *prefix2.OriginValidation)
	}
}

func TestUnicastPrefix_Equal_WithOriginValidation(t *testing.T) {
	tests := []struct {
		name     string
		prefix1  *UnicastPrefix
		prefix2  *UnicastPrefix
		expected bool
	}{
		{
			name: "Equal prefixes with same OV state",
			prefix1: &UnicastPrefix{
				Prefix:           "2001:db8::/32",
				PrefixLen:        32,
				OriginValidation: stringPtr("valid"),
			},
			prefix2: &UnicastPrefix{
				Prefix:           "2001:db8::/32",
				PrefixLen:        32,
				OriginValidation: stringPtr("valid"),
			},
			expected: true,
		},
		{
			name: "Different OV states",
			prefix1: &UnicastPrefix{
				Prefix:           "2001:db8::/32",
				PrefixLen:        32,
				OriginValidation: stringPtr("valid"),
			},
			prefix2: &UnicastPrefix{
				Prefix:           "2001:db8::/32",
				PrefixLen:        32,
				OriginValidation: stringPtr("invalid"),
			},
			expected: false,
		},
		{
			name: "One OV state nil, other set",
			prefix1: &UnicastPrefix{
				Prefix:           "2001:db8::/32",
				PrefixLen:        32,
				OriginValidation: stringPtr("valid"),
			},
			prefix2: &UnicastPrefix{
				Prefix:           "2001:db8::/32",
				PrefixLen:        32,
				OriginValidation: nil,
			},
			expected: false,
		},
		{
			name: "Both OV states nil",
			prefix1: &UnicastPrefix{
				Prefix:           "2001:db8::/32",
				PrefixLen:        32,
				OriginValidation: nil,
			},
			prefix2: &UnicastPrefix{
				Prefix:           "2001:db8::/32",
				PrefixLen:        32,
				OriginValidation: nil,
			},
			expected: true,
		},
		{
			name: "All three states tested",
			prefix1: &UnicastPrefix{
				Prefix:           "2001:db8::/32",
				PrefixLen:        32,
				OriginValidation: stringPtr("not-found"),
			},
			prefix2: &UnicastPrefix{
				Prefix:           "2001:db8::/32",
				PrefixLen:        32,
				OriginValidation: stringPtr("not-found"),
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

func TestL3VPNPrefix_OriginValidationField(t *testing.T) {
	// Test L3VPNPrefix struct with OriginValidation field
	prefix := &L3VPNPrefix{
		Prefix:           "10.1.1.0",
		PrefixLen:        24,
		OriginValidation: stringPtr("invalid"),
		VPNRD:            "65000:100",
	}

	if prefix.OriginValidation == nil {
		t.Fatal("expected OriginValidation field to be set")
	}
	if *prefix.OriginValidation != "invalid" {
		t.Errorf("expected OriginValidation 'invalid', got %q", *prefix.OriginValidation)
	}

	// Test with nil OriginValidation
	prefix2 := &L3VPNPrefix{
		Prefix:           "10.2.2.0",
		PrefixLen:        24,
		OriginValidation: nil,
		VPNRD:            "65000:200",
	}

	if prefix2.OriginValidation != nil {
		t.Errorf("expected OriginValidation field to be nil, got %q", *prefix2.OriginValidation)
	}
}

func TestOriginValidation_AllStates(t *testing.T) {
	// Ensure all three valid states are tested
	states := []string{"valid", "not-found", "invalid"}

	for _, state := range states {
		t.Run("State_"+state, func(t *testing.T) {
			attrs := &bgp.BaseAttributes{
				ExtCommunityList: []string{"ov-state=" + state},
			}

			result := extractOriginValidation(attrs)
			if result == nil {
				t.Fatalf("expected state %q to be extracted, got nil", state)
			}
			if *result != state {
				t.Errorf("expected state %q, got %q", state, *result)
			}
		})
	}
}

func TestOriginValidation_WithColorEC(t *testing.T) {
	// Test that both Color and OriginValidation can coexist
	attrs := &bgp.BaseAttributes{
		ExtCommunityList: []string{"color=100", "ov-state=valid", "rt=65000:100"},
	}

	ovState := extractOriginValidation(attrs)
	color := extractColorEC(attrs)

	if ovState == nil {
		t.Error("expected Origin Validation state to be extracted")
	} else if *ovState != "valid" {
		t.Errorf("expected OriginValidation 'valid', got %q", *ovState)
	}

	if color == nil {
		t.Error("expected Color to be extracted")
	} else if *color != 100 {
		t.Errorf("expected Color 100, got %d", *color)
	}
}
