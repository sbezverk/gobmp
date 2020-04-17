package evpn

import "github.com/sbezverk/gobmp/pkg/base"

// MACIPAdvertisement defines a structure of Route type 2
// (MAC IP Advertisement route)
type MACIPAdvertisement struct {
	RD            *base.RD
	ESI           *ESI
	EthTag        []byte
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

func (t *MACIPAdvertisement) getRD() string {
	return t.RD.String()
}

func (t *MACIPAdvertisement) getESI() *ESI {
	return t.ESI
}

func (t *MACIPAdvertisement) getTag() []byte {
	return nil
}

func (t *MACIPAdvertisement) getMAC() *MACAddress {
	return t.MACAddr
}

func (t *MACIPAdvertisement) getMACLength() *uint8 {
	return &t.MACAddrLength
}

func (t *MACIPAdvertisement) getIPAddress() []byte {
	return t.IPAddr
}

func (t *MACIPAdvertisement) getIPLength() *uint8 {
	return &t.IPAddrLength
}

func (t *MACIPAdvertisement) getGWAddress() []byte {
	return nil
}

func (t *MACIPAdvertisement) getLabel() []*base.Label {
	return t.Label
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
	t.EthTag = make([]byte, 4)
	copy(t.EthTag, b[p:p+4])
	p += 4
	t.MACAddrLength = b[p]
	p++
	l := int(t.MACAddrLength / 8)
	if l != 0 {
		t.MACAddr, err = MakeMACAddress(b[p : p+l])
		if err != nil {
			return nil, err
		}
		p += l
	}
	t.IPAddrLength = b[p]
	p++
	l = int(t.IPAddrLength / 8)
	if t.IPAddrLength != 0 {
		t.IPAddr = make([]byte, l)
		copy(t.IPAddr, b[p:p+l])
		p += l
	}
	for i := 0; p < len(b); i++ {
		l, err := base.MakeLabel(b[p : p+3])
		if err != nil {
			return nil, err
		}
		t.Label = append(t.Label, l)
		p += 3
	}

	return &t, nil
}
