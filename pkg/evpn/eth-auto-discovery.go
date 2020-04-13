package evpn

import "github.com/sbezverk/gobmp/pkg/base"

// EthAutoDiscovery defines a structure of Route type 1
// (Ethernet Auto Discovery route type)
type EthAutoDiscovery struct {
	RD     *base.RD
	ESI    *ESI
	EthTag []byte
	Label  *base.Label
}

// GetRouteTypeSpec returns the instance of a Ethernet Auto Discovery route type object
func (t *EthAutoDiscovery) GetRouteTypeSpec() interface{} {
	return t
}

// UnmarshalEVPNEthAutoDiscovery instantiates new instance of a Ethernet Auto Discovery route type object
func UnmarshalEVPNEthAutoDiscovery(b []byte) (*EthAutoDiscoveryRoute, error) {
	var err error
	t := EthAutoDiscovery{}
	p := 0
	t.RD, err = base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, err
	}
	p += 8
	t.ESI, err = MakeESI(b[p : p+10])
	if err != nil {
		return nil, err
	}
	p += 10
	copy(t1.EthTag, b[p:p+4])
	p += 4
	t.Label, err = base.MakeLabel(b[p:])
	if err != nil {
		return nil, err
	}

	return &t, nil
}
