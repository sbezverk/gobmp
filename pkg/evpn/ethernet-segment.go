package evpn

import "github.com/sbezverk/gobmp/pkg/base"

// EthernetSegment defines a structure of Route type 4
// (Ethernet Segment Route)
type EthernetSegment struct {
	RD           *base.RD
	ESI          *ESI
	IPAddrLength uint8
	IPAddr       []byte
}

// GetRouteTypeSpec returns the instance of the Ethernet Segment Route object
func (t *EthernetSegment) GetRouteTypeSpec() interface{} {
	return t
}

func (t *EthernetSegment) getRD() string {
	return t.RD.String()
}

func (t *EthernetSegment) getESI() *ESI {
	return t.ESI
}

func (t *EthernetSegment) getTag() []byte {
	return nil
}

func (t *EthernetSegment) getMAC() *MACAddress {
	return nil
}

func (t *EthernetSegment) getMACLength() *uint8 {
	return nil
}

func (t *EthernetSegment) getIPAddress() []byte {
	return t.IPAddr
}

func (t *EthernetSegment) getIPLength() *uint8 {
	return &t.IPAddrLength
}

func (t *EthernetSegment) getGWAddress() []byte {
	return nil
}

func (t *EthernetSegment) getLabel() []*base.Label {
	return nil
}

// UnmarshalEVPNEthernetSegment instantiates new instance of an Ethernet Segment Route object
func UnmarshalEVPNEthernetSegment(b []byte) (*EthernetSegment, error) {
	var err error
	t := EthernetSegment{}
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
