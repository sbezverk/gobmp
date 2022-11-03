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
	var err error = nil
	for p := 0; p < len(b); {
		route := Route{}
		route.Length = b[p]
		// Check if there is Path ID in NLRI
		if pathID {
			if p+4 > len(b) {
				err = fmt.Errorf("not enough bytes to reconstruct routes")
				goto error_handle
			}
			route.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
			if p >= len(b) {
				err = fmt.Errorf("not enough bytes to reconstruct routes")
				goto error_handle
			}
			// Updating length
			route.Length = b[p]
		}
		l := route.Length / 8
		if route.Length%8 != 0 {
			l++
		}
		if p+1 > len(b) {
			err = fmt.Errorf("not enough bytes to reconstruct routes")
			goto error_handle
		}
		p++
		// The sum of a current pointer in the slice and safeOffset should not exceed the byte slice length.
		if p+int(l) > len(b) {
			err = fmt.Errorf("not enough bytes to reconstruct route")
			goto error_handle
		}
		route.Prefix = make([]byte, l)
		copy(route.Prefix, b[p:p+int(l)])
		p += int(l)
		routes = append(routes, route)
	}

error_handle:
	if err != nil {
		// In some cases, Error could be triggered by use of incorrect value of PathID flag, as Add Path capability
		// might be advertised and received, but BGP Update would not have PathID set due to some other conditions,
		// example when bgp speakers are in different AS. In error handle, attempting to Unmarshal again with reversed
		// value of PathID flag.
		if r, e := UnmarshalRoutes(b, !pathID); e == nil {
			return r, nil
		}
		glog.Errorf("failed to reconstruct routes from slice %s with error: %+v", tools.MessageHex(b), err)

		return nil, err
	}

	return routes, nil
}
