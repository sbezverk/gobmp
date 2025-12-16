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

// UnmarshalType4 parses Leaf A-D route
func UnmarshalType4(b []byte) (*Type4, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("invalid Type4 length: %d bytes (minimum 4)", len(b))
	}
	t := &Type4{}

	// The Route Key length is variable. The Originating Router's IP is the last 4 or 16 bytes.
	// We need to determine where the Route Key ends and the Originator IP begins.
	// The Originator IP is always either 4 bytes (IPv4) or 16 bytes (IPv6).

	// Try IPv4 (4 bytes) first
	if len(b) >= 4 {
		routeKeyLen := len(b) - 4
		t.RouteKey = make([]byte, routeKeyLen)
		copy(t.RouteKey, b[0:routeKeyLen])
		t.OriginatorIP = make([]byte, 4)
		copy(t.OriginatorIP, b[routeKeyLen:])

		// Validate that the route key makes sense (should start with RD, so at least 8 bytes)
		if routeKeyLen >= 8 {
			return t, nil
		}
	}

	// Try IPv6 (16 bytes)
	if len(b) >= 16 {
		routeKeyLen := len(b) - 16
		if routeKeyLen >= 8 {
			t.RouteKey = make([]byte, routeKeyLen)
			copy(t.RouteKey, b[0:routeKeyLen])
			t.OriginatorIP = make([]byte, 16)
			copy(t.OriginatorIP, b[routeKeyLen:])
			return t, nil
		}
	}

	return nil, fmt.Errorf("invalid Type4 format: cannot determine route key and originator IP boundaries")
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
