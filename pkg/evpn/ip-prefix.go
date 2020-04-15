package evpn

import "github.com/sbezverk/gobmp/pkg/base"

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

func (t *IPPrefix) GetRD() string {
	return t.RD.String()
}

func (t *IPPrefix) GetESI() *ESI {
	return t.ESI
}

func (t *IPPrefix) GetTag() []byte {
	return nil
}

func (t *IPPrefix) GetMAC() *MACAddress {
	return nil
}

func (t *IPPrefix) GetMACLength() *uint8 {
	return nil
}

func (t *IPPrefix) GetIPAddress() []byte {
	return t.IPAddr
}

func (t *IPPrefix) GetIPLength() *uint8 {
	return &t.IPAddrLength
}

func (t *IPPrefix) GetGWAddress() []byte {
	return t.GWIPAddr
}

func (t *IPPrefix) GetLabel() []*base.Label {
	return t.Label
}

// UnmarshalEVPNIPPrefix instantiates new IP Prefix route type object
func UnmarshalEVPNIPPrefix(b []byte) (*IPPrefix, error) {
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
	copy(t.EthTag, b[p:p+4])
	t.IPAddrLength = b[p]
	p++
	l := int(t.IPAddrLength / 8)
	t.IPAddr = make([]byte, l)
	copy(t.IPAddr, b[p:p+l])
	p += l
	t.GWIPAddr = make([]byte, l)
	copy(t.GWIPAddr, b[p:p+l])
	p += l
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
