package evpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// PerRegionIPMSIAD defines a structure of Route type 9
// (Per-Region I-PMSI A-D Route type)
// RFC 9572 Section 3.1
type PerRegionIPMSIAD struct {
	RD       *base.RD
	EthTag   []byte
	RegionID []byte
}

// GetRouteTypeSpec returns the instance of the Per-Region I-PMSI A-D Route type object
func (t *PerRegionIPMSIAD) GetRouteTypeSpec() interface{} {
	return t
}

func (t *PerRegionIPMSIAD) getRD() string {
	return t.RD.String()
}

func (t *PerRegionIPMSIAD) getESI() *ESI {
	return nil
}

func (t *PerRegionIPMSIAD) getTag() []byte {
	return t.EthTag
}

func (t *PerRegionIPMSIAD) getMAC() *MACAddress {
	return nil
}

func (t *PerRegionIPMSIAD) getMACLength() *uint8 {
	return nil
}

func (t *PerRegionIPMSIAD) getIPAddress() []byte {
	return nil
}

func (t *PerRegionIPMSIAD) getIPLength() *uint8 {
	return nil
}

func (t *PerRegionIPMSIAD) getGWAddress() []byte {
	return nil
}

func (t *PerRegionIPMSIAD) getLabel() []*base.Label {
	return nil
}

// UnmarshalEVPNPerRegionIPMSIAD instantiates new instance of a Per-Region I-PMSI A-D Route type object
func UnmarshalEVPNPerRegionIPMSIAD(b []byte) (*PerRegionIPMSIAD, error) {
	// RFC 9572 Section 3.1: Fixed 20-byte structure
	// RD (8) + Ethernet Tag ID (4) + Region ID (8)
	if len(b) != 20 {
		return nil, fmt.Errorf("invalid length %d for Type 9 EVPN NLRI, expected 20 bytes", len(b))
	}

	var err error
	t := PerRegionIPMSIAD{}
	p := 0

	// RD: 8 bytes
	t.RD, err = base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, err
	}
	p += 8

	// Ethernet Tag ID: 4 bytes
	t.EthTag = make([]byte, 4)
	copy(t.EthTag, b[p:p+4])
	p += 4

	// Region ID: 8 bytes (encoded as Extended Community per RFC 9572 Section 6.2)
	t.RegionID = make([]byte, 8)
	copy(t.RegionID, b[p:p+8])

	return &t, nil
}
