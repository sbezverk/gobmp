package bgp

import (
	"testing"
)

// TestEncapExtCommunityTunnelType pins the Encapsulation Extended Community
// (Type 0x03, Sub-Type 0x0c) byte layout from RFC 9012 Section 4.1: the
// 6-octet Value field is Reserved(2)+Reserved(2)+Tunnel Type(2), so the
// tunnel type sits in the LAST two octets of the value, not value[2:4].
func TestEncapExtCommunityTunnelType(t *testing.T) {
	// Type=0x03, Sub-Type=0x0c, Reserved, Reserved, Tunnel Type=8 (VXLAN).
	input := []byte{0x03, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}
	want := "encap=8"

	ext, err := makeExtCommunity(input)
	if err != nil {
		t.Fatalf("makeExtCommunity() error: %v", err)
	}
	if got := ext.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
