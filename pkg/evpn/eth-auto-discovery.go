package evpn

import "github.com/sbezverk/gobmp/pkg/base"

// EthAutoDiscovery defines a structure of Route type 1
// (Ethernet Auto Discovery route type)
type EthAutoDiscovery struct {
	RD     *base.RD
	ESI    *ESI
	EthTag []byte
	Label  []*base.Label
}

// GetRouteTypeSpec returns the instance of a Ethernet Auto Discovery route type object
func (t *EthAutoDiscovery) GetRouteTypeSpec() interface{} {
	return &t
}

func (t *EthAutoDiscovery) getRD() string {
	return t.RD.String()
}

func (t *EthAutoDiscovery) getESI() *ESI {
	return t.ESI
}

func (t *EthAutoDiscovery) getTag() []byte {
	return t.EthTag
}

func (t *EthAutoDiscovery) getMAC() *MACAddress {
	return nil
}

func (t *EthAutoDiscovery) getMACLength() *uint8 {
	return nil
}

func (t *EthAutoDiscovery) getIPAddress() []byte {
	return nil
}

func (t *EthAutoDiscovery) getIPLength() *uint8 {
	return nil
}

func (t *EthAutoDiscovery) getGWAddress() []byte {
	return nil
}

func (t *EthAutoDiscovery) getLabel() []*base.Label {
	return t.Label
}

// UnmarshalEVPNEthAutoDiscovery instantiates new instance of a Ethernet Auto Discovery route type object
func UnmarshalEVPNEthAutoDiscovery(b []byte) (*EthAutoDiscovery, error) {
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
	t.EthTag = make([]byte, 4)
	copy(t.EthTag, b[p:p+4])
	p += 4
	bos := false
	// Loop through labels until hit Bottom of the stack or reach the end of slice
	for !bos && p < len(b) {
		l, err := base.MakeLabel(b[p:])
		if err != nil {
			return nil, err
		}
		t.Label = append(t.Label, l)
		p += 3
		bos = l.BoS
	}

	return &t, nil
}
