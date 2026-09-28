package mcastvpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// rdLen is the Route Distinguisher length in octets (RFC 4364 Section 4.2).
const rdLen = 8

// Type4 defines Leaf A-D route (Route Type 4)
// RFC 6514 Section 4.4
// Format: Route Key (variable) + Originating Router's IP Address (variable)
//
// Per RFC 6514 Section 4.4, the Route Key is set to the NLRI of the received
// Inter-AS/Intra-AS I-PMSI A-D or S-PMSI A-D route that triggered this Leaf
// A-D route. Like every MCAST-VPN NLRI (RFC 6514 Section 4), that referenced
// NLRI carries its own 1-octet Route Type and 1-octet Length fields, so the
// Route Key is self-describing, not "Type 3 without the route type and
// length fields" as a bare value.
type Type4 struct {
	RouteKey     []byte // Referenced route's full NLRI: route type (1) + length (1) + value
	OriginatorIP []byte
}

// UnmarshalType4 parses a Leaf A-D route (RFC 6514 Section 4.4).
//
// The Route Key carries its own type/length header (RFC 6515 Section 2, item
// 4), so it is parsed forward; the Originating Router's IP Address is
// whatever remains and its family is determined by its own length (4 or 16
// octets) -- NOT inferred from the enclosing NLRI's AFI (RFC 6515 Section
// 1/2: "MUST NOT be inferred from the AFI").
//
// RFC 7524 Section 6.2.2 adds a global table multicast (GTM) form whose Route
// Key has no type/length header; it is detected from the first Route Key
// octet: "If the value of this octet is either 0x00 or 0xff, and octets 3
// through 10 contain either all 0x00 or all 0xff, then this is a Leaf A-D
// route used for global table multicast."
func UnmarshalType4(b []byte) (*Type4, error) {
	if isGTMRouteKey(b) {
		return unmarshalType4GTM(b)
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("invalid Type4 length: %d bytes (minimum 2 for Route Key header)", len(b))
	}
	keyLen := 2 + int(b[1])
	if keyLen > len(b) {
		return nil, fmt.Errorf("invalid Type4 Route Key length %d: exceeds remaining %d bytes", b[1], len(b)-2)
	}
	// RFC 7524 Section 6.2.2: "If the value of this octet is 0x01, 0x02, or
	// 0x03, then this Leaf A-D route was originated in response to an S-PMSI
	// or I-PMSI A-D route." Any other non-GTM value is neither form. The
	// embedded route is validated by its own parser, so the RFC 6515 Section 2
	// originator-length rule applies to it as it does to a top-level route.
	var err error
	switch b[0] {
	case 1:
		_, err = UnmarshalType1(b[2:keyLen])
	case 2:
		_, err = UnmarshalType2(b[2:keyLen])
	case 3:
		_, err = UnmarshalType3(b[2:keyLen])
	default:
		return nil, fmt.Errorf("invalid Type4 Route Key route type %d (expected 1, 2 or 3)", b[0])
	}
	if err != nil {
		return nil, fmt.Errorf("invalid Type4 Route Key: embedded route type %d: %w", b[0], err)
	}
	originatorLen := len(b) - keyLen
	if originatorLen != 4 && originatorLen != 16 {
		return nil, fmt.Errorf("invalid originating router IP length: %d bytes (expected 4 or 16)", originatorLen)
	}
	t := &Type4{
		RouteKey:     make([]byte, keyLen),
		OriginatorIP: make([]byte, originatorLen),
	}
	copy(t.RouteKey, b[:keyLen])
	copy(t.OriginatorIP, b[keyLen:])

	return t, nil
}

// isGTMRouteKey reports whether b starts with an RFC 7524 Section 6.2.2 GTM
// Route Key: an 8-octet RD that is all 0x00 or all 0xff. Framed Route Keys
// start with a Route Type of 1-3, so the two forms cannot collide.
func isGTMRouteKey(b []byte) bool {
	if len(b) < rdLen || (b[0] != 0x00 && b[0] != 0xff) {
		return false
	}
	for _, v := range b[1:rdLen] {
		if v != b[0] {
			return false
		}
	}
	return true
}

// gtmAddrLen validates an RFC 7524 Section 6.2.2 Multicast Source/Group
// Length: "Multicast Source Length and Multicast Group Length are set to
// either 4 or 16". The bit lengths (32/128) of RFC 6514 S-PMSI routes and the
// RFC 6625 wildcard (0) belong to other encodings and are rejected here.
func gtmAddrLen(l byte) (int, error) {
	switch l {
	case 4, 16:
		return int(l), nil
	default:
		return 0, fmt.Errorf("invalid GTM multicast address length %d (expected 4 or 16)", l)
	}
}

// unmarshalType4GTM parses an RFC 7524 Section 6.2.2 GTM Leaf A-D route:
// Route Key = RD (8) + Source Length (1) + Source + Group Length (1) + Group +
// Ingress PE IP Address, followed by the Originating Router's IP Address. The
// family of both trailing addresses is "determined from the length of the
// address" (RFC 7524 Section 6.2.2), so the remainder must be 4+4 or 16+16.
func unmarshalType4GTM(b []byte) (*Type4, error) {
	p := rdLen
	for _, field := range []string{"source", "group"} {
		if p >= len(b) {
			return nil, fmt.Errorf("invalid GTM Type4: missing multicast %s length at offset %d", field, p)
		}
		l, err := gtmAddrLen(b[p])
		if err != nil {
			return nil, err
		}
		p++
		if p+l > len(b) {
			return nil, fmt.Errorf("invalid GTM Type4: multicast %s needs %d bytes, %d remaining", field, l, len(b)-p)
		}
		p += l
	}
	var addrLen int
	switch len(b) - p {
	case 8:
		addrLen = 4
	case 32:
		addrLen = 16
	default:
		return nil, fmt.Errorf("invalid GTM Type4: %d bytes for Ingress PE and Originating Router addresses (expected 8 or 32)", len(b)-p)
	}
	keyLen := p + addrLen
	t := &Type4{
		RouteKey:     make([]byte, keyLen),
		OriginatorIP: make([]byte, addrLen),
	}
	copy(t.RouteKey, b[:keyLen])
	copy(t.OriginatorIP, b[keyLen:])

	return t, nil
}

// GetRouteTypeSpec returns the route type specific structure
func (t *Type4) GetRouteTypeSpec() interface{} {
	return t
}

// getRD returns nil (Route Key contains RD but not directly accessible)
func (t *Type4) getRD() *base.RD {
	// The RD is embedded in the Route Key, but we don't parse it here
	return nil
}

// getOriginatorIP returns the Originating Router's IP address
func (t *Type4) getOriginatorIP() []byte {
	return t.OriginatorIP
}

// getMulticastSource returns nil (embedded in Route Key)
func (t *Type4) getMulticastSource() []byte {
	return nil
}

// getMulticastGroup returns nil (embedded in Route Key)
func (t *Type4) getMulticastGroup() []byte {
	return nil
}

// getSourceAS returns 0 (not applicable for Type 4)
func (t *Type4) getSourceAS() uint32 {
	return 0
}
