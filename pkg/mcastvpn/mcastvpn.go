package mcastvpn

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// RouteTypeSpec defines methods to get route type specific information
type RouteTypeSpec interface {
	GetRouteTypeSpec() interface{}
	getRD() *base.RD
	getOriginatorIP() []byte
	getMulticastSource() []byte
	getMulticastGroup() []byte
	getSourceAS() uint32
}

// Route defines a collection of MCAST-VPN NLRI objects of the same type
type Route struct {
	Route []*NLRI
}

// NLRI defines a single MCAST-VPN NLRI object
// RFC 6514 - BGP Encodings and Procedures for Multicast in MPLS/BGP IP VPNs
type NLRI struct {
	RouteType uint8
	Length    uint8
	RouteTypeSpec
}

// GetMCASTVPNRouteType returns the type of MCAST-VPN route
func (n *NLRI) GetMCASTVPNRouteType() uint8 {
	return n.RouteType
}

// GetMCASTVPNRD returns Route Distinguisher if available
func (n *NLRI) GetMCASTVPNRD() *base.RD {
	return n.getRD()
}

// GetMCASTVPNOriginatorIP returns Originating Router's IP address
func (n *NLRI) GetMCASTVPNOriginatorIP() []byte {
	return n.getOriginatorIP()
}

// GetMCASTVPNMulticastSource returns Multicast Source address
func (n *NLRI) GetMCASTVPNMulticastSource() []byte {
	return n.getMulticastSource()
}

// GetMCASTVPNMulticastGroup returns Multicast Group address
func (n *NLRI) GetMCASTVPNMulticastGroup() []byte {
	return n.getMulticastGroup()
}

// GetMCASTVPNSourceAS returns Source AS
func (n *NLRI) GetMCASTVPNSourceAS() uint32 {
	return n.getSourceAS()
}

// UnmarshalMCASTVPNNLRI instantiates a MCAST-VPN NLRI object
func UnmarshalMCASTVPNNLRI(b []byte) (*Route, error) {
	if glog.V(6) {
		glog.Infof("MCAST-VPN NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	r := Route{
		Route: make([]*NLRI, 0),
	}
	for p := 0; p < len(b); {
		if p+2 > len(b) {
			return nil, fmt.Errorf("not enough data for route type and length at position %d", p)
		}
		var err error
		n := &NLRI{}
		n.RouteType = b[p]
		p++
		n.Length = b[p]
		p++
		l := int(n.Length)
		if p+l > len(b) {
			return nil, fmt.Errorf("not enough data for route type %d: need %d bytes, have %d", n.RouteType, l, len(b)-p)
		}
		switch n.RouteType {
		case 1:
			// Intra-AS I-PMSI A-D route
			n.RouteTypeSpec, err = UnmarshalType1(b[p : p+l])
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal type 1 route: %w", err)
			}
		case 2:
			// Inter-AS I-PMSI A-D route
			n.RouteTypeSpec, err = UnmarshalType2(b[p : p+l])
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal type 2 route: %w", err)
			}
		case 3:
			// S-PMSI A-D route
			n.RouteTypeSpec, err = UnmarshalType3(b[p : p+l])
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal type 3 route: %w", err)
			}
		case 4:
			// Leaf A-D route
			n.RouteTypeSpec, err = UnmarshalType4(b[p : p+l])
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal type 4 route: %w", err)
			}
		case 5:
			// Source Active A-D route
			n.RouteTypeSpec, err = UnmarshalType5(b[p : p+l])
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal type 5 route: %w", err)
			}
		case 6:
			// Shared Tree Join route (C-multicast)
			n.RouteTypeSpec, err = UnmarshalType6(b[p : p+l])
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal type 6 route: %w", err)
			}
		case 7:
			// Source Tree Join route (C-multicast)
			n.RouteTypeSpec, err = UnmarshalType7(b[p : p+l])
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal type 7 route: %w", err)
			}
		default:
			return nil, fmt.Errorf("unknown MCAST-VPN route type %d", n.RouteType)
		}
		r.Route = append(r.Route, n)
		p += l
	}

	return &r, nil
}
