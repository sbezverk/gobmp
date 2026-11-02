package bgp

import "testing"

func TestMPReachFlowSpecNextHop(t *testing.T) {
	tests := []struct {
		name string
		afi  uint16
		safi uint8
		nh   []byte
		want string
	}{
		{"IPv4 FlowSpec", 1, 133, nil, ""}, {"IPv6 FlowSpec", 2, 133, nil, ""},
		{"VPNv4 FlowSpec", 1, 134, nil, ""}, {"VPNv6 FlowSpec", 2, 134, nil, ""},
		{"IPv4 unicast empty", 1, 1, nil, "invalid next hop address length: 0"},
		{"IPv6 unicast empty", 2, 1, nil, "invalid next hop address length: 0"},
		{"unknown AFI", 3, 133, nil, "invalid next hop address length: 0"},
		{"unknown SAFI", 1, 135, nil, "invalid next hop address length: 0"},
		{"ordinary IPv4", 1, 1, []byte{192, 0, 2, 1}, "192.0.2.1"},
		{"FlowSpec nonempty IPv4", 1, 133, []byte{192, 0, 2, 1}, "192.0.2.1"},
		{"ordinary IPv6", 2, 1, []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "2001:db8::1"},
		{"FlowSpec nonempty IPv6", 2, 134, []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "2001:db8::1"},
		{"FlowSpec invalid length", 1, 133, make([]byte, 99), "invalid next hop address length: 99"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Decode an actual MP_REACH header so the getter sees wire-validated lengths.
			wire := append([]byte{byte(tt.afi >> 8), byte(tt.afi), tt.safi, byte(len(tt.nh))}, tt.nh...)
			wire = append(wire, 0)
			mp, err := UnmarshalMPReachNLRI(wire, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := mp.GetNextHop(); got != tt.want {
				t.Fatalf("next-hop=%q, want %q", got, tt.want)
			}
		})
	}
}
