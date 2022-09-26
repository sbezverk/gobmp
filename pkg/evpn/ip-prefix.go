package evpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// IPPrefix defines a structure of Route type 5
// (IP Prefix route)
type IPPrefix struct {
	RD           *base.RD
	ESI          *ESI
	EthTag       []byte
	IPAddrLength uint8
	IPAddr       []byte
	GWIPAddr     []byte
	Label        []*base.Label
}

// GetRouteTypeSpec returns the instance of a IP Prefi route type object
func (t *IPPrefix) GetRouteTypeSpec() interface{} {
	return t
}

func (t *IPPrefix) getRD() string {
	return t.RD.String()
}

func (t *IPPrefix) getESI() *ESI {
	return t.ESI
}

func (t *IPPrefix) getTag() []byte {
	return nil
}

func (t *IPPrefix) getMAC() *MACAddress {
	return nil
}

func (t *IPPrefix) getMACLength() *uint8 {
	return nil
}

func (t *IPPrefix) getIPAddress() []byte {
	return t.IPAddr
}

func (t *IPPrefix) getIPLength() *uint8 {
	return &t.IPAddrLength
}

func (t *IPPrefix) getGWAddress() []byte {
	return t.GWIPAddr
}

func (t *IPPrefix) getLabel() []*base.Label {
	return t.Label
}

// UnmarshalEVPNIPPrefix instantiates IP Prefix route type object
func UnmarshalEVPNIPPrefix(b []byte, length int) (*IPPrefix, error) {
	var err error
	t := IPPrefix{}
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
	t.IPAddrLength = b[p]
	p++
	switch length {
	case 34:
		t.IPAddr = make([]byte, 4)
		copy(t.IPAddr, b[p:p+4])
		p += 4
		t.GWIPAddr = make([]byte, 4)
		copy(t.GWIPAddr, b[p:p+4])
		p += 4
	case 58:
		t.IPAddr = make([]byte, 16)
		copy(t.IPAddr, b[p:p+16])
		p += 16
		t.GWIPAddr = make([]byte, 16)
		copy(t.GWIPAddr, b[p:p+16])
		p += 16
	default:
		return nil, fmt.Errorf("unknown evpn ip prefix, length:%d should be 34 for IPv4 or 58 for IPv6", length)
	}
	l, err := base.MakeLabel(b[p:])
	if err != nil {
		return nil, err
	}
	t.Label = append(t.Label, l)
	return &t, nil
}
