package evpn

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// RouteTypeSpec defines a method to get a route type specific information
type RouteTypeSpec interface {
	GetRouteTypeSpec() interface{}
}

// NLRI defines EVPN NLRI object
// https://tools.ietf.org/html/rfc7432
type NLRI struct {
	RouteType uint8
	Length    uint8
	RouteTypeSpec
}

// UnmarshalEVPNNLRI instantiates an EVPN NLRI object
func UnmarshalEVPNNLRI(b []byte) (*NLRI, error) {
	glog.V(5).Infof("EVPN NLRI Raw: %s", tools.MessageHex(b))
	var err error
	n := NLRI{}
	p := 0
	n.RouteType = b[p]
	p++
	n.Length = b[p]
	p++
	switch n.RouteType {
	case 1:
		n.RouteTypeSpec, err = UnmarshalEVPNEthAutoDiscovery(b[p:])
		if err != nil {
			return nil, err
		}
	case 2:
		n.RouteTypeSpec, err = UnmarshalEVPNMACIPAdvertisement(b[p:])
		if err != nil {
			return nil, err
		}
	case 3:
		n.RouteTypeSpec, err = UnmarshalEVPNInclusiveMulticastEthTag(b[p:])
		if err != nil {
			return nil, err
		}
	case 4:
		n.RouteTypeSpec, err = UnmarshalEVPNEthernetSegment(b[p:])
		if err != nil {
			return nil, err
		}
	case 5:
		n.RouteTypeSpec, err = UnmarshalEVPNIPPrefix(b[p:])
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown route type %d", n.RouteType)
	}

	return &n, nil
}

// ESI defines 10 bytes of Ethernet Segment Identifier
type ESI [10]byte

// MakeESI makes an instance of Ethernet Segment Identifier from a slice of bytes
func MakeESI(b []byte) (*ESI, error) {
	if len(b) != 10 {
		return nil, fmt.Errorf("wrong length of slice, expected 10 got %d", len(b))
	}
	esi := ESI{}
	for i := 0; i < len(b); i++ {
		esi[i] = b[i]
	}

	return &esi, nil
}

// MACAddress defines 6 bytes for Ethernet MAC Address field
type MACAddress [6]byte

// MakeMACAddress makes an instance of Ethernet MAC Address from a slice of bytes
func MakeMACAddress(b []byte) (*MACAddress, error) {
	if len(b) != 6 {
		return nil, fmt.Errorf("wrong length of slice, expected 6 got %d", len(b))
	}
	mac := MACAddress{}
	for i := 0; i < len(b); i++ {
		mac[i] = b[i]
	}

	return &mac, nil
}
