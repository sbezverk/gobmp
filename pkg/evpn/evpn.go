package evpn

import "fmt"

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
	var err error
	n := NLRI{}
	p := 0
	n.RouteType = b[p]
	p++
	n.Length = b[p]
	p++
	switch n.RouteType {
	case 1:
		n.RouteTypeSpec, err = UnmarshalEVPNEthAutoDiscoveryRoute(b[p:])
		if err != nil {
			return nil, err
		}
	case 2:
	case 3:
	case 4:
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
