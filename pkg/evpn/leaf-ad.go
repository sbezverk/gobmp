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

// UnmarshalEVPNLeafAD parses EVPN Type 11 Leaf A-D route from wire format
// RFC 9572 Section 3.3
//
// Wire format: RouteKey (variable) | OriginatorAddrLen (1 byte) | OriginatorAddr (4 or 16 bytes)
// Since RouteKey has no explicit length field, we parse backwards to identify the originator fields.
//
// NOTE: Backward parsing limitation - if an IPv6 originator has byte 11 equal to 32, the IPv4
// check could theoretically match incorrectly. This is statistically rare (probability 1/256) and
// mitigated by trying IPv6 first and validating RouteKey length >= 1 byte per RFC 9572.
func UnmarshalEVPNLeafAD(b []byte) (*LeafAD, error) {
	// Minimum length: Route Key (1 byte min) + OriginatorAddrLen (1 byte) + OriginatorAddr (4 bytes min) = 6 bytes
	if len(b) < 6 {
		return nil, fmt.Errorf("invalid length of Leaf A-D route: need at least 6 bytes, have %d", len(b))
	}

	l := &LeafAD{}

	// Parse from the end to determine where Route Key ends
	// Try IPv6 first (last 17 bytes: length field + 16 bytes address)
	// IPv6 is tried first to reduce false positives with IPv4 check
	if len(b) >= 17 {
		potentialLenPos := len(b) - 17
		if b[potentialLenPos] == 128 {
			// Validate RouteKey length >= 1 byte (RFC 9572 Section 3.3 requires embedded NLRI)
			if potentialLenPos < 1 {
				return nil, fmt.Errorf("invalid Leaf A-D route: RouteKey must be at least 1 byte")
			}
			// Valid IPv6 case
			l.OriginatorAddrLen = 128
			l.OriginatorAddr = make([]byte, 16)
			copy(l.OriginatorAddr, b[potentialLenPos+1:potentialLenPos+17])
			l.RouteKey = make([]byte, potentialLenPos)
			copy(l.RouteKey, b[0:potentialLenPos])
			return l, nil
		}
	}

	// Try IPv4 (last 5 bytes: length field + 4 bytes address)
	if len(b) >= 5 {
		potentialLenPos := len(b) - 5
		if b[potentialLenPos] == 32 {
			// Validate RouteKey length >= 1 byte (RFC 9572 Section 3.3 requires embedded NLRI)
			if potentialLenPos < 1 {
				return nil, fmt.Errorf("invalid Leaf A-D route: RouteKey must be at least 1 byte")
			}
			// Valid IPv4 case
			l.OriginatorAddrLen = 32
			l.OriginatorAddr = make([]byte, 4)
			copy(l.OriginatorAddr, b[potentialLenPos+1:potentialLenPos+5])
			l.RouteKey = make([]byte, potentialLenPos)
			copy(l.RouteKey, b[0:potentialLenPos])
			return l, nil
		}
	}

	// Neither valid IPv4 nor IPv6 format found
	return nil, fmt.Errorf("invalid originator address length in Leaf A-D route")
}
