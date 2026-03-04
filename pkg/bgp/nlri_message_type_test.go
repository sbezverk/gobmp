package bgp

import "testing"

// TestNLRIMessageType covers all AFI/SAFI branches in NLRIMessageType.
func TestNLRIMessageType(t *testing.T) {
	tests := []struct {
		name     string
		afi      uint16
		safi     uint8
		wantType int
	}{
		// BGP-LS
		{"BGP-LS AFI=16388 SAFI=71", 16388, 71, 71},

		// IPv4 unicast
		{"IPv4 unicast AFI=1 SAFI=1", 1, 1, 1},
		// IPv6 unicast
		{"IPv6 unicast AFI=2 SAFI=1", 2, 1, 2},

		// IPv4 multicast
		{"IPv4 multicast AFI=1 SAFI=2", 1, 2, 28},
		// IPv6 multicast
		{"IPv6 multicast AFI=2 SAFI=2", 2, 2, 29},

		// MPLS Labels
		{"IPv4 LU AFI=1 SAFI=4", 1, 4, 16},
		{"IPv6 LU AFI=2 SAFI=4", 2, 4, 17},

		// L3VPN
		{"IPv4 L3VPN AFI=1 SAFI=128", 1, 128, 18},
		{"IPv6 L3VPN AFI=2 SAFI=128", 2, 128, 19},

		// VPLS / EVPN
		{"VPLS AFI=25 SAFI=65", 25, 65, 23},
		{"EVPN AFI=25 SAFI=70", 25, 70, 24},

		// SR Policy
		{"SR Policy v4 AFI=1 SAFI=73", 1, 73, 25},
		{"SR Policy v6 AFI=2 SAFI=73", 2, 73, 26},

		// Flowspec
		{"Flowspec IPv4 AFI=1 SAFI=133", 1, 133, 27},
		{"Flowspec IPv6 AFI=2 SAFI=133", 2, 133, 27},
		{"Flowspec VPNv4 AFI=1 SAFI=134", 1, 134, 27},
		{"Flowspec VPNv6 AFI=2 SAFI=134", 2, 134, 27},

		// MCAST-VPN
		{"MCAST-VPN v4 AFI=1 SAFI=5", 1, 5, 32},
		{"MCAST-VPN v6 AFI=2 SAFI=5", 2, 5, 33},

		// Multicast VPN (MVPN)
		{"MVPN v4 AFI=1 SAFI=129", 1, 129, 34},
		{"MVPN v6 AFI=2 SAFI=129", 2, 129, 35},

		// Route Target Constraint
		{"RTC v4 AFI=1 SAFI=132", 1, 132, 30},
		{"RTC v6 AFI=2 SAFI=132", 2, 132, 31},

		// Unknown / unregistered
		{"unknown AFI=0 SAFI=0", 0, 0, 0},
		{"unknown AFI=99 SAFI=99", 99, 99, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NLRIMessageType(tt.afi, tt.safi)
			if got != tt.wantType {
				t.Errorf("NLRIMessageType(%d, %d) = %d, want %d", tt.afi, tt.safi, got, tt.wantType)
			}
		})
	}
}
