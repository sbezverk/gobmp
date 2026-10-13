package bgp

import (
	"fmt"
	"testing"
)

// TestESILabelExtCommunityValue pins the ESI Label Extended Community
// (Type 0x06, Sub-Type 0x01) label decoding from RFC 7432 Section 7.5: the
// 3-octet ESI Label field follows the RFC 3032 label stack entry convention
// used everywhere else in this codebase (base.MakeLabel) - the label value
// occupies the high-order 20 bits, not the raw 24 bits shifted into a uint32.
func TestESILabelExtCommunityValue(t *testing.T) {
	// Type=0x06, Sub-Type=0x01, Flags=0x00, Reserved, Reserved,
	// ESI Label = label 100, Exp=0, BoS=1 -> 100<<4|1 = 0x000641.
	input := []byte{0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x41}
	want := "esi-l=0:100"

	ext, err := makeExtCommunity(input)
	if err != nil {
		t.Fatalf("makeExtCommunity() error: %v", err)
	}
	if got := ext.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

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

func TestEncapExtCommunityShortValue(t *testing.T) {
	// makeExtCommunity enforces 8 octets, so exercise type3 directly.
	for _, value := range [][]byte{{0, 0, 0, 0}, {0, 0, 0, 0, 0}} {
		want := fmt.Sprintf("invalid-type3-length=%d", len(value))
		if got := type3(0x0c, value); got != want {
			t.Errorf("type3(0x0c, % x) = %q, want %q", value, got, want)
		}
	}
}
