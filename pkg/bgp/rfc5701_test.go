package bgp

import (
	"testing"

	"github.com/sbezverk/tools/sort"
)

// RFC 5701 — IPv6 Address Specific Extended Community (Path Attribute 25)
// Each community is 20 bytes: Type(1) + SubType(1) + IPv6 Address(16) + Local Admin(2)

// TestRFC5701_IPv6ExtCommunity_RouteTarget validates parsing a single IPv6 RT extended community.
func TestRFC5701_IPv6ExtCommunity_RouteTarget(t *testing.T) {
	// Type=0x00 (Transitive), SubType=0x02 (Route Target)
	// IPv6=2001:db8::1, LocalAdmin=100
	input := []byte{
		0x00, 0x02, // Type + SubType (Route Target)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001:db8::1
		0x00, 0x64, // Local Admin: 100
	}
	result := unmarshalAttrIPv6ExtCommunity(input)
	if len(result) != 1 {
		t.Fatalf("got %d communities, want 1", len(result))
	}
	expected := "rt=2001:db8::1:100"
	if result[0] != expected {
		t.Errorf("got %q, want %q", result[0], expected)
	}
}

// TestRFC5701_IPv6ExtCommunity_RouteOrigin validates parsing an IPv6 Route Origin community.
func TestRFC5701_IPv6ExtCommunity_RouteOrigin(t *testing.T) {
	// Type=0x00, SubType=0x03 (Route Origin)
	// IPv6=2001:db8::2, LocalAdmin=200
	input := []byte{
		0x00, 0x03, // Type + SubType (Route Origin)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // 2001:db8::2
		0x00, 0xc8, // Local Admin: 200
	}
	result := unmarshalAttrIPv6ExtCommunity(input)
	if len(result) != 1 {
		t.Fatalf("got %d communities, want 1", len(result))
	}
	expected := "ro=2001:db8::2:200"
	if result[0] != expected {
		t.Errorf("got %q, want %q", result[0], expected)
	}
}

// TestRFC5701_IPv6ExtCommunity_Multiple validates parsing two IPv6 extended communities.
func TestRFC5701_IPv6ExtCommunity_Multiple(t *testing.T) {
	input := []byte{
		// Community 1: RT 2001:db8::1:100
		0x00, 0x02,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x64,
		// Community 2: RO 2001:db8::2:200
		0x00, 0x03,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0xc8,
	}
	result := unmarshalAttrIPv6ExtCommunity(input)
	if len(result) != 2 {
		t.Fatalf("got %d communities, want 2", len(result))
	}
}

// TestRFC5701_IPv6ExtCommunity_Empty validates nil return for empty input.
func TestRFC5701_IPv6ExtCommunity_Empty(t *testing.T) {
	result := unmarshalAttrIPv6ExtCommunity(nil)
	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}
	result = unmarshalAttrIPv6ExtCommunity([]byte{})
	if result != nil {
		t.Errorf("expected nil for empty slice, got %v", result)
	}
}

// TestRFC5701_IPv6ExtCommunity_InvalidLength validates partial parse for non-multiple-of-20.
func TestRFC5701_IPv6ExtCommunity_InvalidLength(t *testing.T) {
	// 19 bytes — not a multiple of 20, no complete community
	input := make([]byte, 19)
	result := unmarshalAttrIPv6ExtCommunity(input)
	if result != nil {
		t.Errorf("expected nil for 19 bytes (no complete community), got %v", result)
	}
	// 21 bytes — one complete 20-byte community + 1 trailing byte, logs warning
	input = make([]byte, 21)
	result = unmarshalAttrIPv6ExtCommunity(input)
	if len(result) != 1 {
		t.Errorf("expected 1 community from 21 bytes (one complete + 1 trailing), got %d", len(result))
	}
}

// TestRFC5701_BaseAttributes_Equal_IPv6ExtCommunity validates Equal detects IPv6ExtCommunityList diffs.
func TestRFC5701_BaseAttributes_Equal_IPv6ExtCommunity(t *testing.T) {
	a := &BaseAttributes{
		IPv6ExtCommunityList: []string{"rt=2001:db8::1:100"},
	}
	b := &BaseAttributes{
		IPv6ExtCommunityList: []string{"rt=2001:db8::2:200"},
	}
	eq, diffs := a.Equal(b)
	if eq {
		t.Error("expected not equal for different IPv6ExtCommunityList")
	}
	found := false
	for _, d := range diffs {
		if d == "ipv6_ext_community_list mismatch" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ipv6_ext_community_list mismatch in diffs, got %v", diffs)
	}

	// Same values should be equal
	c := &BaseAttributes{
		IPv6ExtCommunityList: []string{"rt=2001:db8::1:100"},
	}
	eq2, _ := a.Equal(c)
	if !eq2 {
		t.Error("expected equal for same IPv6ExtCommunityList")
	}

	// Suppress unused import
	_ = sort.SortMergeComparableSlice([]string{})
}

// TestRFC5701_IPv6ExtCommunity_UnknownSubType validates handling of unknown sub-type.
func TestRFC5701_IPv6ExtCommunity_UnknownSubType(t *testing.T) {
	input := []byte{
		0x00, 0x0a, // Unknown sub-type 0x0a
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x64,
	}
	result := unmarshalAttrIPv6ExtCommunity(input)
	if len(result) != 1 {
		t.Fatalf("got %d communities, want 1", len(result))
	}
	// Should still parse without error (uses default sub-type format)
	if result[0] == "" {
		t.Error("expected non-empty string for unknown sub-type")
	}
}
