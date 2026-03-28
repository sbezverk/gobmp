package mcastvpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// Type4 defines Leaf A-D route (Route Type 4)
// RFC 6514 Section 4.4
// Format: Route Key (variable) + Originating Router's IP (variable)
// Route Key is the NLRI of the S-PMSI A-D route (Type 3 without the route type and length fields)
type Type4 struct {
	RouteKey     []byte // Contains the referenced S-PMSI A-D route NLRI
	OriginatorIP []byte
}

// UnmarshalType4 parses Leaf A-D route.
// ipv6 indicates AFI=2 from the enclosing MP_REACH/UNREACH, which determines
// whether the Originating Router's IP is 4 bytes (IPv4) or 16 bytes (IPv6).
func UnmarshalType4(b []byte, ipv6 bool) (*Type4, error) {
	ipLen := 4
	if ipv6 {
		ipLen = 16
	}
	minLen := 8 + ipLen // RD (8) + Originator IP (4 or 16)
	ipVersion := "IPv4"
	if ipv6 {
		ipVersion = "IPv6"
	}
	if len(b) < minLen {
		return nil, fmt.Errorf("invalid Type4 length: %d bytes (minimum %d for %s)", len(b), minLen, ipVersion)
	}
	t := &Type4{}
	routeKeyLen := len(b) - ipLen
	t.RouteKey = make([]byte, routeKeyLen)
	copy(t.RouteKey, b[0:routeKeyLen])
	t.OriginatorIP = make([]byte, ipLen)
	copy(t.OriginatorIP, b[routeKeyLen:])
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
