// Package mup implements parsers for BGP MUP SAFI NLRI as defined in
// draft-ietf-bess-mup-safi-01.
//
// The BGP-MUP NLRI is carried in MP_REACH_NLRI/MP_UNREACH_NLRI with an AFI of
// 1 (IPv4) or 2 (IPv6) and the BGP-MUP SAFI. The AFI determines whether the
// addresses carried in the route type specific portion are IPv4 or IPv6.
//
// Wire format of the common header (draft Section 3.1):
//
//	+-----------------------------------+
//	| Architecture Type (1 octet)       |
//	+-----------------------------------+
//	| Route Type (2 octets)             |
//	+-----------------------------------+
//	| Length (1 octet)                  |
//	+-----------------------------------+
//	| Route Type specific (variable)    |
//	+-----------------------------------+
//
// Length covers only the Route Type specific field.
package mup

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// SAFI is the Subsequent Address Family Identifier of BGP-MUP.
const SAFI = 85

// ErrEmptyNLRI is returned when MUP NLRI data has zero length,
// signaling an End-of-RIB marker per RFC 4724 Section 2.
var ErrEmptyNLRI = errors.New("NLRI length is 0")

// Architecture Types for BGP-MUP NLRI per draft Section 3.1
const (
	// ArchType3GPP5G identifies the 3gpp-5g Mobile User Plane architecture
	ArchType3GPP5G = 1
)

// Route Types for BGP-MUP NLRI per draft Section 3.1
const (
	// RouteTypeISD identifies an Interwork Segment Discovery route
	RouteTypeISD = 1
	// RouteTypeDSD identifies a Direct Segment Discovery route
	RouteTypeDSD = 2
	// RouteTypeST1 identifies a Type 1 Session Transformed route
	RouteTypeST1 = 3
	// RouteTypeST2 identifies a Type 2 Session Transformed route
	RouteTypeST2 = 4
)

// RouteTypeSpec defines a method to get a route type specific information
type RouteTypeSpec interface {
	GetRouteTypeSpec() interface{}
	getRD() *base.RD
}

// Route defines a collection of BGP-MUP NLRI objects
type Route struct {
	Route []*NLRI
}

// NLRI defines a single BGP-MUP NLRI object
type NLRI struct {
	// PathID is the Add Path Path Identifier of RFC 7911, it is 0 when the
	// session did not negotiate Add Path for the BGP-MUP SAFI.
	PathID           uint32
	ArchitectureType uint8
	RouteType        uint16
	Length           uint8
	RouteTypeSpec
}

// GetMUPArchitectureType returns the architecture type of the MUP route
func (n *NLRI) GetMUPArchitectureType() uint8 {
	return n.ArchitectureType
}

// GetMUPRouteType returns the type of the MUP route
func (n *NLRI) GetMUPRouteType() uint16 {
	return n.RouteType
}

// GetMUPRD returns Route Distinguisher, all four route types carry one
func (n *NLRI) GetMUPRD() *base.RD {
	return n.getRD()
}

// UnmarshalMUPNLRI instantiates a BGP-MUP NLRI object.
// ipv6 indicates AFI=2, it selects the length of the addresses carried
// in the route type specific portion of each NLRI. pathID indicates that
// Add Path was negotiated for the BGP-MUP SAFI, so every NLRI is prefixed
// with a Path Identifier.
//
// An NLRI of an unknown architecture or route type, or one whose route
// type specific portion is malformed, is skipped and the rest of the
// attribute is still decoded, as draft Section 3.1 requires. Only a
// common header that cannot be read, or a Length that runs past the
// attribute, leaves no way to find the next NLRI and fails the whole
// attribute.
func UnmarshalMUPNLRI(b []byte, ipv6 bool, pathID bool) (*Route, error) {
	if glog.V(6) {
		glog.Infof("MUP NLRI Raw: %s, ipv6: %t, pathID: %t", tools.MessageHex(b), ipv6, pathID)
	}
	if len(b) == 0 {
		return nil, ErrEmptyNLRI
	}
	r := Route{
		Route: make([]*NLRI, 0),
	}
	skipped := 0
	for p := 0; p < len(b); {
		var err error
		n := &NLRI{}
		if pathID {
			if p+4 > len(b) {
				return nil, fmt.Errorf("not enough data for MUP NLRI Path Identifier at position %d: need 4 bytes, have %d", p, len(b)-p)
			}
			n.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}
		if p+4 > len(b) {
			return nil, fmt.Errorf("not enough data for MUP NLRI header at position %d: need 4 bytes, have %d", p, len(b)-p)
		}
		n.ArchitectureType = b[p]
		n.RouteType = binary.BigEndian.Uint16(b[p+1 : p+3])
		n.Length = b[p+3]
		p += 4
		l := int(n.Length)
		if p+l > len(b) {
			return nil, fmt.Errorf("not enough data for MUP route type %d: need %d bytes, have %d", n.RouteType, l, len(b)-p)
		}
		if n.ArchitectureType != ArchType3GPP5G {
			glog.V(4).Infof("skipping MUP NLRI of unknown architecture type %d at position %d", n.ArchitectureType, p-4)
			skipped++
			p += l
			continue
		}
		switch n.RouteType {
		case RouteTypeISD:
			n.RouteTypeSpec, err = UnmarshalISDRoute(b[p:p+l], ipv6)
		case RouteTypeDSD:
			n.RouteTypeSpec, err = UnmarshalDSDRoute(b[p:p+l], ipv6)
		case RouteTypeST1:
			n.RouteTypeSpec, err = UnmarshalST1Route(b[p:p+l], ipv6)
		case RouteTypeST2:
			n.RouteTypeSpec, err = UnmarshalST2Route(b[p:p+l], ipv6)
		default:
			glog.V(4).Infof("skipping MUP NLRI of unknown route type %d at position %d", n.RouteType, p-4)
			skipped++
			p += l
			continue
		}
		if err != nil {
			// Treat-as-withdraw per RFC 7606: the NLRI is dropped, the rest of
			// the attribute is still decoded.
			glog.Warningf("skipping malformed MUP route type %d at position %d: %+v", n.RouteType, p-4, err)
			skipped++
			p += l
			continue
		}
		r.Route = append(r.Route, n)
		p += l
	}
	if len(r.Route) == 0 && skipped > 0 {
		glog.Warningf("MUP NLRI contained only unsupported or malformed routes: %d skipped, no routes decoded", skipped)
	}

	return &r, nil
}

// addrLen returns the length in octets of an address of the NLRI's address family
func addrLen(ipv6 bool) int {
	if ipv6 {
		return 16
	}
	return 4
}

// maskPadding clears the bits past a bit length field. The wire carries whole
// octets and a sender is not required to zero the unused tail, which would
// otherwise leak into the printed value and the route hash.
func maskPadding(b []byte, bits int) {
	if rem := bits % 8; rem != 0 {
		b[bits/8] &= 0xFF << (8 - rem)
	}
}
