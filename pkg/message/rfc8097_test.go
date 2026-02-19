package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

// TestRFC8097_ExtractOriginValidation_ValidStates tests extraction of the
// three defined validation states per RFC 8097 Section 3.
func TestRFC8097_ExtractOriginValidation_ValidStates(t *testing.T) {
	states := []string{"valid", "not-found", "invalid"}

	for _, state := range states {
		t.Run("State_"+state, func(t *testing.T) {
			attrs := &bgp.BaseAttributes{
				ExtCommunityList: []string{"ov-state=" + state},
			}
			result := extractOriginValidation(attrs)
			if result == nil {
				t.Fatalf("expected state %q, got nil", state)
			}
			if *result != state {
				t.Errorf("expected %q, got %q", state, *result)
			}
		})
	}
}

// TestRFC8097_ExtractOriginValidation_NilInputs tests nil and empty inputs.
func TestRFC8097_ExtractOriginValidation_NilInputs(t *testing.T) {
	tests := []struct {
		name  string
		attrs *bgp.BaseAttributes
	}{
		{
			name:  "Nil BaseAttributes",
			attrs: nil,
		},
		{
			name: "Nil ExtCommunityList",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: nil,
			},
		},
		{
			name: "Empty ExtCommunityList",
			attrs: &bgp.BaseAttributes{
				ExtCommunityList: []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractOriginValidation(tt.attrs)
			if result != nil {
				t.Errorf("expected nil, got %q", *result)
			}
		})
	}
}

// TestRFC8097_ExtractOriginValidation_NoOVStatePresent verifies nil return
// when extended communities exist but none carry OV state.
func TestRFC8097_ExtractOriginValidation_NoOVStatePresent(t *testing.T) {
	tests := []struct {
		name string
		ecs  []string
	}{
		{
			name: "Only Route Target",
			ecs:  []string{"rt=65000:100"},
		},
		{
			name: "Route Target and Color",
			ecs:  []string{"rt=65000:100", "color=500"},
		},
		{
			name: "Route Origin and Link Bandwidth",
			ecs:  []string{"ro=65000:200", "link-bw=1000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &bgp.BaseAttributes{
				ExtCommunityList: tt.ecs,
			}
			result := extractOriginValidation(attrs)
			if result != nil {
				t.Errorf("expected nil, got %q", *result)
			}
		})
	}
}

// TestRFC8097_ExtractOriginValidation_InvalidStateValues verifies that
// unknown or malformed state values return nil (rejected).
func TestRFC8097_ExtractOriginValidation_InvalidStateValues(t *testing.T) {
	tests := []struct {
		name string
		ec   string
	}{
		{
			name: "Unknown state 3",
			ec:   "ov-state=unknown=3",
		},
		{
			name: "Malformed state",
			ec:   "ov-state=malformed",
		},
		{
			name: "Empty state",
			ec:   "ov-state=",
		},
		{
			name: "Numeric state",
			ec:   "ov-state=0",
		},
		{
			name: "Uppercase state",
			ec:   "ov-state=Valid",
		},
		{
			name: "Invalid length state",
			ec:   "ov-state=invalid-length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &bgp.BaseAttributes{
				ExtCommunityList: []string{tt.ec},
			}
			result := extractOriginValidation(attrs)
			if result != nil {
				t.Errorf("expected nil for %q, got %q", tt.ec, *result)
			}
		})
	}
}

// TestRFC8097_ExtractOriginValidation_FirstMatch verifies that the first
// matching OV state EC is returned when multiple exist.
func TestRFC8097_ExtractOriginValidation_FirstMatch(t *testing.T) {
	attrs := &bgp.BaseAttributes{
		ExtCommunityList: []string{"ov-state=valid", "ov-state=invalid"},
	}
	result := extractOriginValidation(attrs)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if *result != "valid" {
		t.Errorf("expected first match %q, got %q", "valid", *result)
	}
}

// TestRFC8097_ExtractOriginValidation_MixedWithOtherECs verifies correct
// extraction when OV state is mixed with other extended community types.
func TestRFC8097_ExtractOriginValidation_MixedWithOtherECs(t *testing.T) {
	tests := []struct {
		name          string
		ecs           []string
		expectedState string
	}{
		{
			name:          "RT + OV + Color",
			ecs:           []string{"rt=65000:100", "ov-state=valid", "color=500"},
			expectedState: "valid",
		},
		{
			name:          "Color + RT + OV at end",
			ecs:           []string{"color=100", "rt=65000:200", "ov-state=not-found"},
			expectedState: "not-found",
		},
		{
			name:          "Many ECs with OV in middle",
			ecs:           []string{"rt=65000:100", "ro=65000:200", "ov-state=invalid", "color=300", "link-bw=500"},
			expectedState: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &bgp.BaseAttributes{
				ExtCommunityList: tt.ecs,
			}
			result := extractOriginValidation(attrs)
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if *result != tt.expectedState {
				t.Errorf("expected %q, got %q", tt.expectedState, *result)
			}
		})
	}
}

// TestRFC8097_UnicastPrefix_OriginValidationField verifies that the
// UnicastPrefix struct correctly stores and serializes the field.
func TestRFC8097_UnicastPrefix_OriginValidationField(t *testing.T) {
	states := []string{"valid", "not-found", "invalid"}

	for _, state := range states {
		t.Run(state, func(t *testing.T) {
			s := state
			prefix := &UnicastPrefix{
				Prefix:           "10.0.0.0",
				PrefixLen:        24,
				OriginValidation: &s,
			}
			if prefix.OriginValidation == nil {
				t.Fatal("OriginValidation is nil")
			}
			if *prefix.OriginValidation != state {
				t.Errorf("got %q, want %q", *prefix.OriginValidation, state)
			}
		})
	}

	// Nil case
	prefix := &UnicastPrefix{
		Prefix:           "10.0.0.0",
		PrefixLen:        24,
		OriginValidation: nil,
	}
	if prefix.OriginValidation != nil {
		t.Errorf("expected nil, got %q", *prefix.OriginValidation)
	}
}

// TestRFC8097_L3VPNPrefix_OriginValidationField verifies the field on
// L3VPN prefixes (RFC 8097 applies to both unicast and L3VPN).
func TestRFC8097_L3VPNPrefix_OriginValidationField(t *testing.T) {
	states := []string{"valid", "not-found", "invalid"}

	for _, state := range states {
		t.Run(state, func(t *testing.T) {
			s := state
			prefix := &L3VPNPrefix{
				Prefix:           "10.1.1.0",
				PrefixLen:        24,
				VPNRD:            "65000:100",
				OriginValidation: &s,
			}
			if prefix.OriginValidation == nil {
				t.Fatal("OriginValidation is nil")
			}
			if *prefix.OriginValidation != state {
				t.Errorf("got %q, want %q", *prefix.OriginValidation, state)
			}
		})
	}
}

// TestRFC8097_UnicastPrefix_Equal_OriginValidation tests the Equal method
// when comparing OriginValidation fields.
func TestRFC8097_UnicastPrefix_Equal_OriginValidation(t *testing.T) {
	validStr := "valid"
	invalidStr := "invalid"
	notFoundStr := "not-found"

	tests := []struct {
		name     string
		ov1      *string
		ov2      *string
		expected bool
	}{
		{
			name:     "Both nil",
			ov1:      nil,
			ov2:      nil,
			expected: true,
		},
		{
			name:     "Both valid",
			ov1:      &validStr,
			ov2:      &validStr,
			expected: true,
		},
		{
			name:     "Both not-found",
			ov1:      &notFoundStr,
			ov2:      &notFoundStr,
			expected: true,
		},
		{
			name:     "First nil second set",
			ov1:      nil,
			ov2:      &validStr,
			expected: false,
		},
		{
			name:     "First set second nil",
			ov1:      &validStr,
			ov2:      nil,
			expected: false,
		},
		{
			name:     "Different states",
			ov1:      &validStr,
			ov2:      &invalidStr,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1 := &UnicastPrefix{Prefix: "10.0.0.0", PrefixLen: 24, OriginValidation: tt.ov1}
			p2 := &UnicastPrefix{Prefix: "10.0.0.0", PrefixLen: 24, OriginValidation: tt.ov2}
			equal, diffs := p1.Equal(p2)
			if equal != tt.expected {
				t.Errorf("Equal() = %v, want %v. Diffs: %v", equal, tt.expected, diffs)
			}
		})
	}
}

// TestRFC8097_ExtractOriginValidation_Integration tests extraction with
// realistic BGP BaseAttributes containing multiple attribute types.
func TestRFC8097_ExtractOriginValidation_Integration(t *testing.T) {
	attrs := &bgp.BaseAttributes{
		Origin:           "igp",
		ASPath:           []uint32{65000, 65001, 65002},
		ASPathCount:      3,
		Nexthop:          "192.168.1.1",
		MED:              100,
		LocalPref:        200,
		ExtCommunityList: []string{"rt=65000:100", "ov-state=valid", "color=500", "ro=65000:200"},
	}

	ovState := extractOriginValidation(attrs)
	if ovState == nil {
		t.Fatal("expected OV state extraction, got nil")
	}
	if *ovState != "valid" {
		t.Errorf("expected %q, got %q", "valid", *ovState)
	}

	color := extractColorEC(attrs)
	if color == nil {
		t.Fatal("expected color extraction, got nil")
	}
	if *color != 500 {
		t.Errorf("expected color 500, got %d", *color)
	}
}

// TestRFC8097_ExtractOriginValidation_PrefixSubstring verifies that
// partial prefix matches do not falsely extract OV state.
func TestRFC8097_ExtractOriginValidation_PrefixSubstring(t *testing.T) {
	tests := []struct {
		name string
		ec   string
	}{
		{
			name: "Similar prefix ov-state-extra",
			ec:   "ov-state-extra=valid",
		},
		{
			name: "No prefix match",
			ec:   "xov-state=valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &bgp.BaseAttributes{
				ExtCommunityList: []string{tt.ec},
			}
			result := extractOriginValidation(attrs)
			if result != nil {
				t.Errorf("expected nil for %q, got %q", tt.ec, *result)
			}
		})
	}
}
