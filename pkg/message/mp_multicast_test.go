package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestMulticast_IPv4NLRI_IPv4NextHop verifies the canonical AFI 1 / SAFI 2
// case: IPv4 NLRI with a 4-byte IPv4 next hop.
func TestMulticast_IPv4NLRI_IPv4NextHop(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	reachBytes := []byte{
		0x00, 0x01, // AFI: 1
		0x02,                   // SAFI: 2 (multicast)
		0x04,                   // NH Length: 4
		0x0a, 0x00, 0x00, 0x01, // NextHop: 10.0.0.1
		0x00,                   // Reserved
		0x18, 0xe0, 0x01, 0x01, // /24 prefix: 224.1.1.0/24
	}
	nlri, err := bgp.UnmarshalMPReachNLRI(reachBytes, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}

	msgs, err := p.multicast(nlri, 0, ph, update)
	if err != nil {
		t.Fatalf("multicast() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("multicast() returned %d messages, want 1", len(msgs))
	}
	r := msgs[0]
	if !r.IsIPv4 {
		t.Error("IsIPv4 = false, want true")
	}
	if !r.IsNexthopIPv4 {
		t.Error("IsNexthopIPv4 = false, want true for IPv4 next hop")
	}
	if r.Nexthop != "10.0.0.1" {
		t.Errorf("Nexthop = %q, want %q", r.Nexthop, "10.0.0.1")
	}
	if r.Prefix != "224.1.1.0" {
		t.Errorf("Prefix = %q, want %q", r.Prefix, "224.1.1.0")
	}
}

// TestMulticast_IPv6NLRI_IPv6NextHop verifies the canonical AFI 2 / SAFI 2
// case: IPv6 NLRI with a 16-byte IPv6 next hop.
func TestMulticast_IPv6NLRI_IPv6NextHop(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	reachBytes := []byte{
		0x00, 0x02, // AFI: 2
		0x02, // SAFI: 2 (multicast)
		0x10, // NH Length: 16
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // NextHop: 2001:db8::1
		0x00,                                                 // Reserved
		0x40, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // /64 prefix: ff05::/64
	}
	nlri, err := bgp.UnmarshalMPReachNLRI(reachBytes, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}

	msgs, err := p.multicast(nlri, 0, ph, update)
	if err != nil {
		t.Fatalf("multicast() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("multicast() returned %d messages, want 1", len(msgs))
	}
	r := msgs[0]
	if r.IsIPv4 {
		t.Error("IsIPv4 = true, want false")
	}
	if r.IsNexthopIPv4 {
		t.Error("IsNexthopIPv4 = true, want false for IPv6 next hop")
	}
	if r.Nexthop != "2001:db8::1" {
		t.Errorf("Nexthop = %q, want %q", r.Nexthop, "2001:db8::1")
	}
	if r.Prefix != "ff05::" {
		t.Errorf("Prefix = %q, want %q", r.Prefix, "ff05::")
	}
}

// TestMulticast_IPv4NLRI_IPv6NextHop_Mismatch verifies next-hop family comes
// from the next-hop length (RFC 8950 §3), not the NLRI AFI: an AFI 1 (IPv4)
// multicast route can carry a 16-byte IPv6 next hop.
func TestMulticast_IPv4NLRI_IPv6NextHop_Mismatch(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	reachBytes := []byte{
		0x00, 0x01, // AFI: 1 (IPv4 NLRI)
		0x02, // SAFI: 2 (multicast)
		0x10, // NH Length: 16
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // NextHop: 2001:db8::1
		0x00,                   // Reserved
		0x18, 0xe0, 0x01, 0x01, // /24 prefix: 224.1.1.0/24
	}
	nlri, err := bgp.UnmarshalMPReachNLRI(reachBytes, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}

	msgs, err := p.multicast(nlri, 0, ph, update)
	if err != nil {
		t.Fatalf("multicast() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("multicast() returned %d messages, want 1", len(msgs))
	}
	r := msgs[0]
	if !r.IsIPv4 {
		t.Error("IsIPv4 = false, want true (IPv4 NLRI)")
	}
	if r.IsNexthopIPv4 {
		t.Error("IsNexthopIPv4 = true, want false (16-byte IPv6 next hop)")
	}
	if r.Nexthop != "2001:db8::1" {
		t.Errorf("Nexthop = %q, want %q", r.Nexthop, "2001:db8::1")
	}
}

// TestMulticast_IPv6NLRI_MappedIPv4NextHop_Mismatch verifies an AFI 2 (IPv6)
// multicast route with an IPv4-mapped-IPv6 next hop (::ffff:192.0.2.1, per
// RFC 8950 §3 / RFC 4291 §2.5.5.2) is reported as an IPv4 next hop.
func TestMulticast_IPv6NLRI_MappedIPv4NextHop_Mismatch(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	reachBytes := []byte{
		0x00, 0x02, // AFI: 2 (IPv6 NLRI)
		0x02, // SAFI: 2 (multicast)
		0x10, // NH Length: 16
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x01, // NextHop: ::ffff:192.0.2.1
		0x00,                                                 // Reserved
		0x40, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // /64 prefix: ff05::/64
	}
	nlri, err := bgp.UnmarshalMPReachNLRI(reachBytes, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}

	msgs, err := p.multicast(nlri, 0, ph, update)
	if err != nil {
		t.Fatalf("multicast() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("multicast() returned %d messages, want 1", len(msgs))
	}
	r := msgs[0]
	if r.IsIPv4 {
		t.Error("IsIPv4 = true, want false (IPv6 NLRI)")
	}
	if !r.IsNexthopIPv4 {
		t.Error("IsNexthopIPv4 = false, want true (IPv4-mapped-IPv6 next hop)")
	}
	if r.Nexthop != "192.0.2.1" {
		t.Errorf("Nexthop = %q, want %q", r.Nexthop, "192.0.2.1")
	}
}

// TestMulticast_Withdraw_NoNextHop verifies the no-next-hop case that
// l3-vpn.go also handles: MP_UNREACH_NLRI carries no next hop field
// (RFC 4760 §3), so IsNexthopIPv4 falls back to the NLRI's own IsIPv4.
func TestMulticast_Withdraw_NoNextHop(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

	unreachBytes := []byte{
		0x00, 0x02, // AFI: 2 (IPv6 NLRI)
		0x02,                                                 // SAFI: 2 (multicast)
		0x40, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // /64 prefix: ff05::/64
	}
	nlri, err := bgp.UnmarshalMPUnReachNLRI(unreachBytes, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPUnReachNLRI: %v", err)
	}

	msgs, err := p.multicast(nlri, 1, ph, update)
	if err != nil {
		t.Fatalf("multicast() error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("multicast() returned %d messages, want 1", len(msgs))
	}
	r := msgs[0]
	if r.Nexthop != "" {
		t.Errorf("Nexthop = %q, want empty for MP_UNREACH", r.Nexthop)
	}
	if r.IsIPv4 {
		t.Error("IsIPv4 = true, want false for IPv6 withdrawal")
	}
	if r.IsNexthopIPv4 {
		t.Error("IsNexthopIPv4 = true, want false for IPv6 withdrawal without next hop")
	}
}
