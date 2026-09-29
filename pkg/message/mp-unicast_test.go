package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestUnicast_NexthopFamilyWire drives unicast() with MP_REACH_NLRI and
// MP_UNREACH_NLRI values decoded by the real bgp parsers, so the Length of
// Next Hop field and ::ffff: mapping logic (RFC 8950 §3, RFC 4798 §2) are
// exercised rather than a mocked IsNextHopIPv6().
func TestUnicast_NexthopFamilyWire(t *testing.T) {
	v6NH := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	v6LL := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	mappedNH := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1}
	reach := func(afi, safi byte, nh, nlri []byte) []byte {
		b := []byte{0, afi, safi, byte(len(nh))}
		b = append(b, nh...)
		b = append(b, 0) // Reserved
		return append(b, nlri...)
	}
	v4NLRI := []byte{24, 10, 0, 0}                                   // 10.0.0.0/24
	v6NLRI := []byte{32, 0x20, 0x01, 0x0d, 0xb8}                     // 2001:db8::/32
	v6LUNLRI := []byte{56, 0x00, 0x01, 0x01, 0x20, 0x01, 0x0d, 0xb8} // label 16, BoS + 2001:db8::/32

	tests := []struct {
		name          string
		reach         bool
		attr          []byte
		label         bool
		wantPrefix    string
		wantIsIPv4    bool
		wantNexthop   string
		wantNexthopV4 bool
	}{
		{
			name:          "AFI 1 with 4-byte next hop",
			reach:         true,
			attr:          reach(1, 1, []byte{192, 0, 2, 1}, v4NLRI),
			wantPrefix:    "10.0.0.0",
			wantIsIPv4:    true,
			wantNexthop:   "192.0.2.1",
			wantNexthopV4: true,
		},
		{
			name:          "AFI 1 with 16-byte IPv6 next hop (RFC 8950)",
			reach:         true,
			attr:          reach(1, 1, v6NH, v4NLRI),
			wantPrefix:    "10.0.0.0",
			wantIsIPv4:    true,
			wantNexthop:   "2001:db8::1",
			wantNexthopV4: false,
		},
		{
			name:          "AFI 1 with 32-byte global + link-local next hop",
			reach:         true,
			attr:          reach(1, 1, append(append([]byte{}, v6NH...), v6LL...), v4NLRI),
			wantPrefix:    "10.0.0.0",
			wantIsIPv4:    true,
			wantNexthop:   "2001:db8::1,fe80::1",
			wantNexthopV4: false,
		},
		{
			name:          "AFI 2 with IPv4-mapped ::ffff: next hop",
			reach:         true,
			attr:          reach(2, 1, mappedNH, v6NLRI),
			wantPrefix:    "2001:db8::",
			wantIsIPv4:    false,
			wantNexthop:   "192.0.2.1",
			wantNexthopV4: true,
		},
		{
			name:          "6PE: AFI 2 SAFI 4 with IPv4-mapped ::ffff: next hop",
			reach:         true,
			attr:          reach(2, 4, mappedNH, v6LUNLRI),
			label:         true,
			wantPrefix:    "2001:db8::",
			wantIsIPv4:    false,
			wantNexthop:   "192.0.2.1",
			wantNexthopV4: true,
		},
		{
			name:          "AFI 2 with 16-byte IPv6 next hop",
			reach:         true,
			attr:          reach(2, 1, v6NH, v6NLRI),
			wantPrefix:    "2001:db8::",
			wantIsIPv4:    false,
			wantNexthop:   "2001:db8::1",
			wantNexthopV4: false,
		},
		{
			name:          "MP_UNREACH AFI 1 withdrawal has no next hop",
			attr:          append([]byte{0, 1, 1}, v4NLRI...),
			wantPrefix:    "10.0.0.0",
			wantIsIPv4:    true,
			wantNexthopV4: true,
		},
		{
			name:          "MP_UNREACH AFI 2 withdrawal has no next hop",
			attr:          append([]byte{0, 2, 1}, v6NLRI...),
			wantPrefix:    "2001:db8::",
			wantIsIPv4:    false,
			wantNexthopV4: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nlri bgp.MPNLRI
			var err error
			op := 1
			if tt.reach {
				op = 0
				nlri, err = bgp.UnmarshalMPReachNLRI(tt.attr, false, map[int]bool{})
			} else {
				nlri, err = bgp.UnmarshalMPUnReachNLRI(tt.attr, map[int]bool{})
			}
			if err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			p := NewProducer(&mockPublisher{}, false).(*producer)
			ph := makePeerHeader(t, bmp.PeerType0, 0x00)
			update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

			msgs, err := p.unicast(nlri, op, ph, update, tt.label)
			if err != nil {
				t.Fatalf("unicast() error: %v", err)
			}
			if len(msgs) != 1 {
				t.Fatalf("unicast() returned %d messages, want 1", len(msgs))
			}
			r := msgs[0]
			if r.Prefix != tt.wantPrefix {
				t.Errorf("Prefix = %q, want %q", r.Prefix, tt.wantPrefix)
			}
			if r.IsIPv4 != tt.wantIsIPv4 {
				t.Errorf("IsIPv4 = %v, want %v", r.IsIPv4, tt.wantIsIPv4)
			}
			if r.Nexthop != tt.wantNexthop {
				t.Errorf("Nexthop = %q, want %q", r.Nexthop, tt.wantNexthop)
			}
			if r.IsNexthopIPv4 != tt.wantNexthopV4 {
				t.Errorf("IsNexthopIPv4 = %v, want %v", r.IsNexthopIPv4, tt.wantNexthopV4)
			}
		})
	}
}

// TestUnicast_NexthopFamily verifies IsNexthopIPv4 is derived from the next
// hop's own length/value (RFC 8950 §3, RFC 4798 §2), never from the NLRI AFI
// (mockMPNLRI.isIPv6).
func TestUnicast_NexthopFamily(t *testing.T) {
	tests := []struct {
		name          string
		isIPv6        bool // NLRI AFI: false=AFI 1, true=AFI 2
		nextHop       string
		isNextHopIPv6 bool
		wantIsIPv4    bool
		wantNexthopV4 bool
	}{
		{
			name:          "canonical IPv4 NLRI + IPv4 next hop",
			isIPv6:        false,
			nextHop:       "192.0.2.1",
			isNextHopIPv6: false,
			wantIsIPv4:    true,
			wantNexthopV4: true,
		},
		{
			name:          "canonical IPv6 NLRI + IPv6 next hop",
			isIPv6:        true,
			nextHop:       "2001:db8::1",
			isNextHopIPv6: true,
			wantIsIPv4:    false,
			wantNexthopV4: false,
		},
		{
			name:          "mismatched: AFI 1 NLRI with 16-byte IPv6 next hop",
			isIPv6:        false,
			nextHop:       "2001:db8::1",
			isNextHopIPv6: true,
			wantIsIPv4:    true,
			wantNexthopV4: false,
		},
		{
			name:          "6PE-style: AFI 2 NLRI with ::ffff: mapped IPv4 next hop",
			isIPv6:        true,
			nextHop:       "192.0.2.1",
			isNextHopIPv6: false,
			wantIsIPv4:    false,
			wantNexthopV4: true,
		},
		{
			name:          "withdraw, no next hop, IPv4 NLRI",
			isIPv6:        false,
			nextHop:       "",
			isNextHopIPv6: false,
			wantIsIPv4:    true,
			wantNexthopV4: true,
		},
		{
			name:          "withdraw, no next hop, IPv6 NLRI",
			isIPv6:        true,
			nextHop:       "",
			isNextHopIPv6: false,
			wantIsIPv4:    false,
			wantNexthopV4: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProducer(&mockPublisher{}, false).(*producer)
			ph := makePeerHeader(t, bmp.PeerType0, 0x00)
			update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{}}

			prefix := make([]byte, 4)
			length := uint8(24)
			if tt.isIPv6 {
				prefix = make([]byte, 16)
				length = 64
			}
			nlri := &mockMPNLRI{
				isIPv6:        tt.isIPv6,
				nextHop:       tt.nextHop,
				isNextHopIPv6: tt.isNextHopIPv6,
				unicastRoute: &base.MPNLRI{
					NLRI: []base.Route{{Length: length, Prefix: prefix}},
				},
			}

			msgs, err := p.unicast(nlri, 0, ph, update, false)
			if err != nil {
				t.Fatalf("unicast() error: %v", err)
			}
			if len(msgs) != 1 {
				t.Fatalf("unicast() returned %d messages, want 1", len(msgs))
			}
			r := msgs[0]
			if r.IsIPv4 != tt.wantIsIPv4 {
				t.Errorf("IsIPv4 = %v, want %v", r.IsIPv4, tt.wantIsIPv4)
			}
			if r.IsNexthopIPv4 != tt.wantNexthopV4 {
				t.Errorf("IsNexthopIPv4 = %v, want %v", r.IsNexthopIPv4, tt.wantNexthopV4)
			}
			if r.Nexthop != tt.nextHop {
				t.Errorf("Nexthop = %q, want %q", r.Nexthop, tt.nextHop)
			}
		})
	}
}
