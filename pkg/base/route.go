package base

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// MPNLRI defines a collection of Prefixes/Routes sent in NLRI of MP_REACH or MP_UNREACH attribute
type MPNLRI struct {
	NLRI []Route
}

// Route defines a structure of NLRI prefix element
type Route struct {
	PathID uint32
	Length uint8
	// Used in Labeled Unicast and L3VPN NLRI
	Label []*Label
	// Used in Labeled L3VPN NLRI
	RD     *RD
	Prefix []byte
}

// UnmarshalRoutes builds BGP Withdrawn routes object
func UnmarshalRoutes(b []byte) ([]Route, error) {
	routes := make([]Route, 0)
	if len(b) == 0 {
		return nil, nil
	}
	glog.V(6).Infof("Routes Raw: %s", tools.MessageHex(b))
	for p := 0; p < len(b); {
		route := Route{}
		route.Length = b[p]
		// Check if there is Path ID in NLRI
		if b[p] == 0 && len(b) > 4 {
			route.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}
		l := route.Length / 8
		if route.Length%8 != 0 {
			l++
		}
		p++
		// Check that the following copy would not exceed the slice capacity
		safeOffset := int(l)
		// The sum of a current pointer in the slice and safeOffset should not exceed  the byte slice length.
		if p+safeOffset > len(b) {
			safeOffset = len(b) - p
		}
		route.Prefix = make([]byte, l)
		copy(route.Prefix, b[p:p+safeOffset])
		p += safeOffset
		routes = append(routes, route)
	}

	return routes, nil
}
