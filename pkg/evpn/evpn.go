package evpn

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// RouteTypeSpec defines a method to get a route type specific information
type RouteTypeSpec interface {
	GetRouteTypeSpec() interface{}
	getRD() string
	getESI() *ESI
	getTag() []byte
	getMAC() *MACAddress
	getMACLength() *uint8
	getIPAddress() []byte
	getIPLength() *uint8
	getGWAddress() []byte
	getLabel() []*base.Label
}

// Route defines a collection of EVPN NLRI objects of the same type
type Route struct {
	Route []*NLRI
}

// NLRI defines a single EVPN NLRI object
// https://tools.ietf.org/html/rfc7432
type NLRI struct {
	RouteType uint8
	Length    uint8
	RouteTypeSpec
}

// GetEVPNRouteType returns the type of EVPN route
func (n *NLRI) GetEVPNRouteType() uint8 {
	return n.RouteType
}

// GetEVPNRD returns a string representation of RD if available
func (n *NLRI) GetEVPNRD() string {
	return n.RouteTypeSpec.getRD()
}

// GetEVPNESI returns Ethernet Segment Identifier
func (n *NLRI) GetEVPNESI() *ESI {
	return n.RouteTypeSpec.getESI()
}

// GetEVPNTAG returns Ethernet TAG
func (n *NLRI) GetEVPNTAG() []byte {
	return n.RouteTypeSpec.getTag()
}

// GetEVPNMAC returns Ethernet MAC object
func (n *NLRI) GetEVPNMAC() *MACAddress {
	return n.RouteTypeSpec.getMAC()
}

// GetEVPNMACLength returns Ethernet MAC length in bits
func (n *NLRI) GetEVPNMACLength() *uint8 {
	return n.RouteTypeSpec.getMACLength()
}

// GetEVPNIPAddr returns IP Address object
func (n *NLRI) GetEVPNIPAddr() []byte {
	return n.RouteTypeSpec.getIPAddress()
}

// GetEVPNIPLength returns IP Address length in bits
func (n *NLRI) GetEVPNIPLength() *uint8 {
	return n.RouteTypeSpec.getIPLength()
}

// GetEVPNGWAddr returns IP Address of Gateway
func (n *NLRI) GetEVPNGWAddr() []byte {
	return n.RouteTypeSpec.getGWAddress()
}

// GetEVPNLabel returns stack of labels found in the nlri
func (n *NLRI) GetEVPNLabel() []*base.Label {
	return n.RouteTypeSpec.getLabel()
}

// UnmarshalEVPNNLRI instantiates an EVPN NLRI object
func UnmarshalEVPNNLRI(b []byte) (*Route, error) {
	if glog.V(6) {
		glog.Infof("EVPN NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	r := Route{
		Route: make([]*NLRI, 0),
	}
	for p := 0; p < len(b); {
		var err error
		n := &NLRI{}
		n.RouteType = b[p]
		p++
		n.Length = b[p]
		p++
		l := int(n.Length)
		switch n.RouteType {
		case 1:
			n.RouteTypeSpec, err = UnmarshalEVPNEthAutoDiscovery(b[p : p+l])
			if err != nil {
				return nil, err
			}
		case 2:
			n.RouteTypeSpec, err = UnmarshalEVPNMACIPAdvertisement(b[p : p+l])
			if err != nil {
				return nil, err
			}
		case 3:
			n.RouteTypeSpec, err = UnmarshalEVPNInclusiveMulticastEthTag(b[p : p+l])
			if err != nil {
				return nil, err
			}
		case 4:
			n.RouteTypeSpec, err = UnmarshalEVPNEthernetSegment(b[p : p+l])
			if err != nil {
				return nil, err
			}
		case 5:
			n.RouteTypeSpec, err = UnmarshalEVPNIPPrefix(b[p:p+l], l)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown route type %d", n.RouteType)
		}
		r.Route = append(r.Route, n)
		p += l
	}

	return &r, nil
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
