package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestUnicast_NexthopFamily verifies IsNexthopIPv4 is derived from the next
// hop's own length/value (RFC 8950 §3, RFC 4798 §2), never from the NLRI AFI
// (mockMPNLRI.isIPv6). AF-1 in docs/af-discriminator-audit.md.
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
