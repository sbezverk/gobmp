package base

import (
	"encoding/binary"
	"errors"
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

var errPrefixTooLong = errors.New("prefix length over address size")

// UnmarshalRoutesAF builds BGP routes. A prefix longer than 32 bits, or 128 for
// ipv6, makes the field malformed (RFC 4271 §4.3, RFC 4760 §5, RFC 7606 §5.3)
// and is not retried with a flipped Path ID.
func UnmarshalRoutesAF(b []byte, pathID bool, ipv6 bool) ([]Route, error) {
	maxBits := uint8(32)
	if ipv6 {
		maxBits = 128
	}
	return unmarshalRoutes(b, pathID, true, maxBits)
}

func unmarshalRoutes(b []byte, pathID bool, canRetry bool, maxBits uint8) ([]Route, error) {
	if glog.V(6) {
		glog.Infof("Routes Raw: %s Path ID flag: %t", tools.MessageHex(b), pathID)
	}
	// Handle EoR case.
	routes := make([]Route, 0, len(b)/4)
	if len(b) == 0 {
		return routes, nil
	}
	var err error = nil
	for p := 0; p < len(b); {
		route := Route{}
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
		}
		// Updating length
		route.Length = b[p]
		if route.Length > maxBits {
			err = fmt.Errorf("%w: %d bits over %d", errPrefixTooLong, route.Length, maxBits)
			goto error_handle
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
		if route.Length%8 != 0 {
			// RFC 4271 Section 4.3: trailing bits are not part of the prefix.
			route.Prefix[l-1] &= 0xFF << (8 - route.Length%8)
		}
		p += int(l)
		routes = append(routes, route)
	}

error_handle:
	if err != nil {
		// In some cases, Error could be triggered by use of incorrect value of PathID flag, as Add Path capability
		// might be advertised and received, but BGP Update would not have PathID set due to some other conditions,
		// example when bgp speakers are in different AS. In error handle, attempting to Unmarshal again with reversed
		// value of PathID flag.
		if canRetry && !errors.Is(err, errPrefixTooLong) {
			if r, e := unmarshalRoutes(b, !pathID, false, maxBits); e == nil {
				return r, nil
			}
		}
		glog.Errorf("failed to reconstruct routes from slice %s with error: %+v", tools.MessageHex(b), err)

		return nil, err
	}

	return routes, nil
}
