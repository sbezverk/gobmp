package bgp

import (
	"net"
	"reflect"
	"testing"
)

// ipv6ECAttr builds an IPv6 Address Specific Extended Community path attribute
// (type 25, RFC 5701) carrying one 20-octet community.
func ipv6ECAttr(typ, subType byte, addr string, localAdmin uint16) []byte {
	ec := []byte{typ, subType}
	ec = append(ec, net.ParseIP(addr).To16()...)
	ec = append(ec, byte(localAdmin>>8), byte(localAdmin))
	return append([]byte{0xc0, 25, byte(len(ec))}, ec...)
}

// FlowSpec rt-redirect-ipv6 is the transitive IPv6 Address Specific Extended
// Community sub-type 0x0d (RFC 8956 Section 6.1). The non-transitive 0x400d is
// unassigned.
func TestIPv6ExtCommunity_FlowspecRedirect(t *testing.T) {
	tests := []struct {
		name         string
		typ, subType byte
		localAdmin   uint16
		want         string
	}{
		{"rt-redirect-ipv6", 0x00, 0x0d, 100, "flowspec-redirect=2001:db8::1:100"},
		{"rt-redirect-ipv6 local admin 1", 0x00, 0x0d, 1, "flowspec-redirect=2001:db8::1:1"},
		{"non-transitive 0x0d unassigned", 0x40, 0x0d, 100, "subtype-13=2001:db8::1:100"},
		{"sub-type 0x0c not defined by an RFC", 0x00, 0x0c, 100, "subtype-12=2001:db8::1:100"},
		{"route target unchanged", 0x00, 0x02, 100, "rt=2001:db8::1:100"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := UnmarshalBGPBaseAttributes(ipv6ECAttr(tt.typ, tt.subType, "2001:db8::1", tt.localAdmin))
			if err != nil {
				t.Fatalf("UnmarshalBGPBaseAttributes: %v", err)
			}
			if want := []string{tt.want}; !reflect.DeepEqual(attrs.IPv6ExtCommunityList, want) {
				t.Errorf("IPv6ExtCommunityList = %v, want %v", attrs.IPv6ExtCommunityList, want)
			}
		})
	}
}

func TestIPv6ExtCommunity_ShortValue(t *testing.T) {
	if got := ipv6ExtCommunity(0x00, 0x0d, make([]byte, 17)); got != "invalid-ipv6-ec-length" {
		t.Errorf("got %q, want invalid-ipv6-ec-length", got)
	}
}
