package bgp

import (
	"encoding/hex"
	"testing"
)

// TestExtCommunityString checks the strings the fmt based formatting
// produced, one case per formatting branch.
func TestExtCommunityString(t *testing.T) {
	tests := []struct {
		typ, sub byte
		value    string
		want     string
	}{
		{0x00, 0x02, "fde900000001", "rt=65001:1"},
		{0x00, 0x04, "fde93fc00000", "link-bw=1.500000"},
		{0x00, 0x04, "fde97fc00000", "link-bw=NaN"},
		{0x01, 0x02, "c0000201002a", "rt=192.0.2.1:42"},
		{0x02, 0x02, "0000fde9002a", "rt=65001:42"},
		{0x03, 0x0b, "0000006400ff", "color=100"},
		{0x03, 0x0c, "000000000008", "encap=8"},
		{0x03, 0x00, "0000006400ff", "Subtype unknown=100"},
		{0x03, 0x0c, "0000", "invalid-type3-length=2"},
		{0x0c, 0x00, "fde900000005", "mup-ds=65001:5"},
		{0x0c, 0x01, "c0000201002a", "mup-ds=192.0.2.1:42"},
		{0x0c, 0x02, "0000fde9002a", "mup-ds=65001:42"},
		{0x0c, 0x09, "0000fde9002a", "Subtype unknown=65001:42"},
		{0x06, 0x01, "01000012345f", "esi-l=1:74565"},
		{0x06, 0x00, "000000000005", "macmob=0:5"},
		{0x06, 0x06, "00ab12000000", "df-elect=0:0xab12"},
		{0x06, 0x10, "0001000003e8", "evpn-link-bw=4294968296 Mbps"},
		{0x06, 0x10, "0101000003e8", "evpn-link-bw=weight 4294968296"},
		{0x06, 0x10, "0201000003e8", "evpn-link-bw=units=2 weight=4294968296"},
		{0x06, 0x99, "0a0b0c0d0e0f", "Subtype unknown=168496141"},
		{0x40, 0x04, "fde93fc00000", "link-bw=1.500000"},
		{0x40, 0x01, "0000006400ff", "Subtype unknown=100"},
		{0x43, 0x00, "000000000000", "ov-state=valid"},
		{0x43, 0x00, "000000000001", "ov-state=not-found"},
		{0x43, 0x00, "000000000002", "ov-state=invalid"},
		{0x43, 0x00, "000000000003", "ov-state=unknown=3"},
		{0x43, 0x01, "000000000000", "Subtype unknown=unknown-subtype=1"},
		{0x80, 0x06, "fde946fa0000", "flowspec-traffic-rate=AS: 65001 Rate: 256000 bps"},
		{0x80, 0x08, "fde900000005", "flowspec-redirect=65001:5"},
		{0x80, 0x07, "000000000003", "flowspec-traffic-action=T=true S=true"},
		{0x80, 0x09, "0000000000ff", "flowspec-traffic-remarking=DSCP=63"},
		{0x80, 0x06, "0102", "flowspec-traffic-rate=invalid value length of 2"},
		{0x81, 0x08, "c0000201002a", "flowspec-redirect=192.0.2.1:42"},
		{0x81, 0x08, "01", "flowspec-redirect=invalid value length of 1"},
		{0x82, 0x08, "0000fde9002a", "flowspec-redirect=65001:42"},
		{0x82, 0x08, "01", "flowspec-redirect=invalid value length of 1"},
		{0xaa, 0x02, "0a0b0c0d0e0f", "unknown=Type: 170 Subtype: 2 Value: [ 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F ]"},
	}
	for _, tt := range tests {
		v, _ := hex.DecodeString(tt.value)
		ext := &ExtCommunity{Type: tt.typ, SubType: &tt.sub, Value: v}
		if got := ext.String(); got != tt.want {
			t.Errorf("type %#x sub-type %#x value %s: got %q, want %q", tt.typ, tt.sub, tt.value, got, tt.want)
		}
	}
	// A short value, and no sub-type, which is formatted as 0xff.
	for typ, n := range map[byte]string{0x00: "0", 0x01: "1", 0x02: "2", 0x06: "6", 0x0c: "12", 0x40: "40"} {
		ext := &ExtCommunity{Type: typ, Value: []byte{1, 2, 3}}
		if got, want := ext.String(), "invalid-type"+n+"-length=3"; got != want {
			t.Errorf("type %#x: got %q, want %q", typ, got, want)
		}
	}
	if got, want := (&ExtCommunity{Type: 0xaa, Value: []byte{1}}).String(), "unknown=Type: 170 Subtype: 255 Value: [ 0x01 ]"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLgCommunityString(t *testing.T) {
	for lg, want := range map[LgCommunity]string{
		{0, 0, 0}:                            "0:0:0",
		{65001, 1, 10}:                       "65001:1:10",
		{4294967295, 4294967295, 4294967295}: "4294967295:4294967295:4294967295",
	} {
		if got := lg.String(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
