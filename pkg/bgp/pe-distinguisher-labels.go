package bgp

import (
	"fmt"
	"net"
	"net/netip"
)

const (
	peDistLabelSize4 = 4 + 3  // IPv4 PE address + 3 octet label
	peDistLabelSize6 = 16 + 3 // IPv6 PE address + 3 octet label
)

// lookupOriginatorLen is a variable so tests can count invocations.
// Tests that replace it must not run in parallel.
var lookupOriginatorLen = mcastVPNOriginatorLen

// PEDistinguisherLabel is a single {PE Address, Label} pair of the RFC 6514 §8
// PE Distinguisher Labels attribute.
type PEDistinguisherLabel struct {
	PEAddress string `json:"pe_address"`
	Label     uint32 `json:"label"` // 20-bit label value
}

// mcastVPNOriginatorLen returns the length (4 or 16) of the Originating Router's
// IP Address of the first MCAST-VPN route carried in MP_REACH_NLRI within attrs,
// or 0 when there is none. Attribute order is irrelevant.
// The first MCAST-VPN route with an originator decides the family; route types
// without one (2, 5-7) are skipped.
// A parse failure of MP_REACH_NLRI deliberately falls back to the length rule;
// add-path is ignored, as in the main SAFI 5 path.
func mcastVPNOriginatorLen(attrs []PathAttribute) int {
	for _, a := range attrs {
		if a.AttributeType != 14 {
			continue
		}
		mp, err := UnmarshalMPReachNLRI(a.Attribute, false, nil)
		if err != nil {
			continue
		}
		// GetNLRIMCASTVPN rejects anything other than AFI 1/2 with SAFI 5.
		r, err := mp.GetNLRIMCASTVPN()
		if err != nil {
			continue
		}
		for _, n := range r.Route {
			if l := len(n.GetMCASTVPNOriginatorIP()); l == net.IPv4len || l == net.IPv6len {
				return l
			}
		}
	}
	return 0
}

// unmarshalPEDistinguisherLabels decodes RFC 6514 §8 PE Distinguisher Labels.
// originatorLen returns the PE address length (4 or 16) dictated by the carrying
// MCAST-VPN route, or 0 if none; it is only called for plausible lengths.
// Without an MCAST-VPN originator the family is inferred from the attribute
// length when unambiguous.
func unmarshalPEDistinguisherLabels(b []byte, originatorLen func() int) ([]PEDistinguisherLabel, error) {
	m4, m6 := len(b) > 0 && len(b)%peDistLabelSize4 == 0, len(b) > 0 && len(b)%peDistLabelSize6 == 0
	if !m4 && !m6 {
		return nil, fmt.Errorf("length %d is not a multiple of %d or %d", len(b), peDistLabelSize4, peDistLabelSize6)
	}
	addrLen := originatorLen()
	if addrLen == 0 {
		switch {
		case m4 && !m6:
			addrLen = net.IPv4len
		case m6 && !m4:
			addrLen = net.IPv6len
		default:
			return nil, fmt.Errorf("cannot determine address family from length %d", len(b))
		}
	}
	size := addrLen + 3
	if len(b)%size != 0 {
		return nil, fmt.Errorf("length %d is not a multiple of %d", len(b), size)
	}
	out := make([]PEDistinguisherLabel, 0, len(b)/size)
	for p := 0; p < len(b); p += size {
		var addr netip.Addr
		if addrLen == net.IPv4len {
			addr = netip.AddrFrom4([4]byte(b[p : p+addrLen]))
		} else {
			addr = netip.AddrFrom16([16]byte(b[p : p+addrLen]))
		}
		if addr.IsUnspecified() || addr.IsMulticast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return nil, fmt.Errorf("PE address %v at offset %d is not unicast", addr, p)
		}
		l := b[p+addrLen : p+size]
		out = append(out, PEDistinguisherLabel{
			PEAddress: addr.String(),
			Label:     (uint32(l[0])<<16 | uint32(l[1])<<8 | uint32(l[2])) >> 4,
		})
	}
	return out, nil
}
