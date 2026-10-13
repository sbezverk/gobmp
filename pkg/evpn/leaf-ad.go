package evpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// LeafAD defines EVPN Type 11 - Leaf A-D Route
// RFC 9572 Section 3.3
type LeafAD struct {
	RouteKey          []byte // Variable-length embedded NLRI of triggering PMSI route
	OriginatorAddrLen uint8  // Length in bits: 32 or 128
	OriginatorAddr    []byte // 4 or 16 bytes based on OriginatorAddrLen
}

// GetRouteTypeSpec returns the route type spec object
func (l *LeafAD) GetRouteTypeSpec() interface{} {
	return l
}

// getRD returns nil as Leaf A-D route does not have a separate RD field
// (RD is embedded in the Route Key)
func (l *LeafAD) getRD() string {
	return ""
}

// getESI returns nil as Leaf A-D route does not have ESI
func (l *LeafAD) getESI() *ESI {
	return nil
}

// getTag returns nil as Leaf A-D route does not have a separate tag field
// (tag is embedded in the Route Key)
func (l *LeafAD) getTag() []byte {
	return nil
}

// getMAC returns nil as Leaf A-D route does not have MAC
func (l *LeafAD) getMAC() *MACAddress {
	return nil
}

// getMACLength returns nil as Leaf A-D route does not have MAC
func (l *LeafAD) getMACLength() *uint8 {
	return nil
}

// getIPAddress returns nil as Leaf A-D route does not have IP address
func (l *LeafAD) getIPAddress() []byte {
	return nil
}

// getIPLength returns nil as Leaf A-D route does not have IP length
func (l *LeafAD) getIPLength() *uint8 {
	return nil
}

// getGWAddress returns nil as Leaf A-D route does not have gateway address
func (l *LeafAD) getGWAddress() []byte {
	return nil
}

// getLabel returns nil as Leaf A-D route does not have labels
func (l *LeafAD) getLabel() []*base.Label {
	return nil
}

// UnmarshalEVPNLeafAD parses EVPN Type 11 Leaf A-D route from wire format.
// RFC 9572 Section 3.3:
//
//	+-----------------------------------+
//	|      Route Key (variable)         |
//	+-----------------------------------+
//	|Originator's Addr Length (1 octet) |
//	+-----------------------------------+
//	|Originator's Addr (4 or 16 octets) |
//	+-----------------------------------+
//
// RFC 9572 Section 3.3: "The Route Key is the NLRI of the route for which
// this Leaf A-D route is generated." RFC 9572 Section 2 states the Leaf A-D
// route's "NLRI embeds the entire NLRI of the triggering PMSI A-D route."
// RFC 9572 Section 3 (quoting RFC 7432) defines that embedded NLRI as
// Route Type (1 octet) + Length (1 octet) + Route Type specific (variable).
// The Route Key is therefore self-describing: it MUST be parsed forward
// from its own Length field, never guessed by scanning backward from the
// end of the buffer for a byte that merely looks like an originator length.
func UnmarshalEVPNLeafAD(b []byte) (*LeafAD, error) {
	// Route Key must contain at least its own Type(1) + Length(1) header.
	if len(b) < 2 {
		return nil, fmt.Errorf("invalid length of Leaf A-D route: need at least 2 bytes for Route Key header, have %d", len(b))
	}
	// The Route Key "is the NLRI of the route for which this Leaf A-D route
	// is generated" (RFC 9572 Section 3.3); every EVPN route type has a
	// non-empty Route Type specific field, so a zero Length embeds no route.
	// The embedded Route Type is not restricted: Section 3.3 allows "other
	// types of routes that may be defined in the future".
	if b[1] == 0 {
		return nil, fmt.Errorf("invalid Leaf A-D Route Key: embedded route type %d has zero length", b[0])
	}
	keyLen := 2 + int(b[1])
	if keyLen > len(b) {
		return nil, fmt.Errorf("invalid length of Leaf A-D route: Route Key declares %d bytes, have %d remaining", keyLen, len(b))
	}

	rem := b[keyLen:]
	if len(rem) < 1 {
		return nil, fmt.Errorf("invalid length of Leaf A-D route: missing Originator's Addr Length byte")
	}
	origLen := rem[0]
	var addrBytes int
	switch origLen {
	case 32:
		addrBytes = 4
	case 128:
		addrBytes = 16
	default:
		return nil, fmt.Errorf("invalid originator address length in Leaf A-D route: %d, want 32 or 128", origLen)
	}
	if len(rem)-1 != addrBytes {
		return nil, fmt.Errorf("invalid length of Leaf A-D route: originator address length %d requires %d bytes, have %d", origLen, addrBytes, len(rem)-1)
	}

	l := &LeafAD{
		RouteKey:          make([]byte, keyLen),
		OriginatorAddrLen: origLen,
		OriginatorAddr:    make([]byte, addrBytes),
	}
	copy(l.RouteKey, b[:keyLen])
	copy(l.OriginatorAddr, rem[1:])

	return l, nil
}
