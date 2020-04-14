package evpn

import "github.com/sbezverk/gobmp/pkg/base"

// InclusiveMulticastEthTag defines a structure of Route type 3
// (Inclusive Multicast Ethernet Tag Route type)
type InclusiveMulticastEthTag struct {
	RD           *base.RD
	EthTag       []byte
	IPAddrLength uint8
	IPAddr       []byte
}

// GetRouteTypeSpec returns the instance of the Inclusive Multicast Ethernet Tag Route type object
func (t *InclusiveMulticastEthTag) GetRouteTypeSpec() interface{} {
	return t
}

// UnmarshalEVPNInclusiveMulticastEthTag instantiates new instance of an Inclusive Multicast Ethernet Tag Route type object
func UnmarshalEVPNInclusiveMulticastEthTag(b []byte) (*InclusiveMulticastEthTag, error) {
	var err error
	t := InclusiveMulticastEthTag{}
	p := 0
	t.RD, err = base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, err
	}
	p += 8
	copy(t.EthTag, b[p:p+4])
	p += 4
	t.IPAddrLength = b[p]
	p++
	l := int(t.IPAddrLength / 8)
	if t.IPAddrLength != 0 {
		t.IPAddr = make([]byte, l)
		copy(t.IPAddr, b[p:p+l])
		p += l
	}

	return &t, nil
}
