package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
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
func UnmarshalRoutes(b []byte, pathID bool) ([]Route, error) {
	if glog.V(6) {
		glog.Infof("Routes Raw: %s Path ID flag: %t", tools.MessageHex(b), pathID)
	}
	routes := make([]Route, 0)
	if len(b) == 0 {
		return nil, nil
	}
	for p := 0; p < len(b); {
		route := Route{}
		route.Length = b[p]
		// Check if there is Path ID in NLRI
		if pathID {
			// Check for More or Equal to protect from the length of 4 bytes, with PathID true
			// there should be 5 bytes.
			if p+4 >= len(b) {
				// Attempt to unmarshal routes with inversed pathID flag, if succeeded, return error as nil
				if r, err := UnmarshalRoutes(b, !pathID); err == nil {
					return r, nil
				}
				glog.Errorf("UnmarshalRoutes: malformed byte slice %s Path ID flag: %t", tools.MessageHex(b), pathID)
				return nil, fmt.Errorf("malformed byte slice")
			}
			route.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
			// Updating length
			route.Length = b[p]
		}
		l := route.Length / 8
		if route.Length%8 != 0 {
			l++
		}
		p++
		// The sum of a current pointer in the slice and safeOffset should not exceed the byte slice length.
		if p+int(l) > len(b) {
			// Attempt to unmarshal routes with inversed pathID flag, if succeeded, return error as nil
			if r, err := UnmarshalRoutes(b, !pathID); err == nil {
				return r, nil
			}
			glog.Errorf("UnmarshalRoutes: malformed byte slice %s Path ID flag: %t", tools.MessageHex(b), pathID)
			return nil, fmt.Errorf("malformed byte slice")
		}
		route.Prefix = make([]byte, l)
		copy(route.Prefix, b[p:p+int(l)])
		p += int(l)
		routes = append(routes, route)
	}

	return routes, nil
}
