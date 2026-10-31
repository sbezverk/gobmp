package bgp

import (
	"errors"
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

// peDistLabelsOriginatorConflict is returned by mcastVPNOriginatorLen when the
// MCAST-VPN routes in one UPDATE carry Originating Router's IP Addresses of
// different families.
const peDistLabelsOriginatorConflict = -1

// mcastVPNOriginatorLen returns the length (4 or 16) of the Originating Router's
// IP Address of every MCAST-VPN route carried in MP_REACH_NLRI within attrs,
// 0 when no route has one, or peDistLabelsOriginatorConflict when the routes
// disagree. RFC 6514 §8 requires the PE addresses to match the family of the
// Originating Router's IP Address of the route carrying the attribute, and the
// attribute is shared by every route of the UPDATE. Attribute order is irrelevant.
// Route types without an originator (RFC 6514 §4.2 Inter-AS I-PMSI A-D, §4.5
// Source Active A-D, §4.6 C-multicast) are skipped.
// A parse failure of MP_REACH_NLRI deliberately falls back to the length rule;
// add-path is ignored, as in the main SAFI 5 path.
func mcastVPNOriginatorLen(attrs []PathAttribute) int {
	found := 0
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
			l := len(n.GetMCASTVPNOriginatorIP())
			if l != net.IPv4len && l != net.IPv6len {
				continue
			}
			if found != 0 && found != l {
				return peDistLabelsOriginatorConflict
			}
			found = l
		}
	}
	return found
}

// errPEDistLabelsFamilyUnknown reports a length that fits both families when no
// MCAST-VPN route gives an Originating Router's IP Address. RFC 6514 §8 length
// rules (a) and (b) need an expected family, so the attribute is not malformed;
// it cannot be decoded and is discarded.
var errPEDistLabelsFamilyUnknown = errors.New("cannot determine PE address family")

// unmarshalPEDistinguisherLabels decodes RFC 6514 §8 PE Distinguisher Labels.
// originatorLen returns the PE address length (4 or 16) dictated by the carrying
// MCAST-VPN routes, 0 if none, or peDistLabelsOriginatorConflict if they differ;
// it is only called for plausible non-zero lengths.
// Without an MCAST-VPN originator the family is inferred from the attribute
// length when unambiguous.
func unmarshalPEDistinguisherLabels(b []byte, originatorLen func() int) ([]PEDistinguisherLabel, error) {
	// RFC 6514 §8: a zero length is a multiple of 7 and 19 and has no PE
	// Address field, so it is a valid empty list.
	if len(b) == 0 {
		return nil, nil
	}
	m4, m6 := len(b)%peDistLabelSize4 == 0, len(b)%peDistLabelSize6 == 0
	if !m4 && !m6 {
		return nil, fmt.Errorf("length %d is not a multiple of %d or %d", len(b), peDistLabelSize4, peDistLabelSize6)
	}
	addrLen := originatorLen()
	if addrLen == peDistLabelsOriginatorConflict {
		return nil, fmt.Errorf("MCAST-VPN routes mix IPv4 and IPv6 originating router addresses")
	}
	if addrLen == 0 {
		switch {
		case m4 && !m6:
			addrLen = net.IPv4len
		case m6 && !m4:
			addrLen = net.IPv6len
		default:
			// RFC 6514 §8: malformed under both readings is malformed whatever
			// the family; otherwise the family is undecidable.
			_, err4 := decodePEDistinguisherLabels(b, net.IPv4len)
			_, err6 := decodePEDistinguisherLabels(b, net.IPv6len)
			if err4 != nil && err6 != nil {
				return nil, fmt.Errorf("PE addresses are not unicast as IPv4 (%v) or IPv6 (%v)", err4, err6)
			}
			return nil, fmt.Errorf("%w from length %d", errPEDistLabelsFamilyUnknown, len(b))
		}
	}
	return decodePEDistinguisherLabels(b, addrLen)
}

// decodePEDistinguisherLabels decodes b as entries with addrLen-octet PE addresses.
func decodePEDistinguisherLabels(b []byte, addrLen int) ([]PEDistinguisherLabel, error) {
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
