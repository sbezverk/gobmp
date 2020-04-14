package evpn

import "github.com/sbezverk/gobmp/pkg/base"

// MACIPAdvertisement defines a structure of Route type 2
// (MAC IP Advertisement route)
type MACIPAdvertisement struct {
	RD            *base.RD
	ESI           *ESI
	MACAddrLength uint8
	MACAddr       *MACAddress
	IPAddrLength  uint8
	IPAddr        []byte
	Label         []*base.Label
}

// GetRouteTypeSpec returns the instance of a MAC IP Advertisement route type object
func (t *MACIPAdvertisement) GetRouteTypeSpec() interface{} {
	return t
}

// UnmarshalEVPNMACIPAdvertisement instantiates new instance of a Ethernet Auto Discovery route type object
func UnmarshalEVPNMACIPAdvertisement(b []byte) (*MACIPAdvertisement, error) {
	var err error
	t := MACIPAdvertisement{}
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
	t.MACAddrLength = b[p]
	p++
	t.MACAddr, err = MakeMACAddress(b[p : p+6])
	if err != nil {
		return nil, err
	}
	p += 6
	t.IPAddrLength = b[p]
	p++
	if t.IPAddrLength != 0 {
		t.IPAddr = make([]byte, int(t.IPAddrLength))
		copy(t.IPAddr, b[p:p+int(t.IPAddrLength)])
		p += int(t.IPAddrLength)
	}
	for i := 0; p < len(b); i++ {
		l, err := base.MakeLabel(b[p:])
		if err != nil {
			return nil, err
		}
		t.Label = append(t.Label, l)
		p += 3
	}

	return &t, nil
}
