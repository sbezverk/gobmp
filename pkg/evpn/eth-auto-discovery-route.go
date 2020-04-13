package evpn

import "github.com/sbezverk/gobmp/pkg/base"

// EthAutoDiscoveryRoute defines a structure of Route type 1
// (Ethernet Auto Discovery route type)
type EthAutoDiscoveryRoute struct {
	RD     *base.RD
	ESI    *ESI
	EthTag []byte
	Label  *base.Label
}

// GetRouteTypeSpec returns the instance of a Ethernet Auto Discovery route type object
func (t1 *EthAutoDiscoveryRoute) GetRouteTypeSpec() interface{} {
	return t1
}

// UnmarshalEVPNEthAutoDiscoveryRoute instantiates new instance of a Ethernet Auto Discovery route type object
func UnmarshalEVPNEthAutoDiscoveryRoute(b []byte) (*EthAutoDiscoveryRoute, error) {
	var err error
	t1 := EthAutoDiscoveryRoute{}
	p := 0
	t1.RD, err = base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, err
	}
	p += 8
	t1.ESI, err = MakeESI(b[p : p+10])
	if err != nil {
		return nil, err
	}
	p += 10
	copy(t1.EthTag, b[p:p+4])
	p += 4
	t1.Label, err = base.MakeLabel(b[p:])
	if err != nil {
		return nil, err
	}
	return &t1, nil
}
