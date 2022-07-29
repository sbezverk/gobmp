package bgp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/prefixsid"
	"github.com/sbezverk/tools"
)

const (
	MP_REACH_NLRI   = 14
	MP_UNREACH_NLRI = 15
	BGP4_NLRI       = 0
)

// Update defines a structure of BGP Update message
type Update struct {
	WithdrawnRoutesLength    uint16
	WithdrawnRoutes          []byte
	TotalPathAttributeLength uint16
	PathAttributes           []PathAttribute
	NLRI                     []byte
	BaseAttributes           *BaseAttributes
}

// GetAllAttributeID return a slixe of int with all attributes found in BGP Update
func (up *Update) GetAllAttributeID() []uint8 {
	attrs := make([]uint8, 0)
	for _, attr := range up.PathAttributes {
		attrs = append(attrs, attr.AttributeType)
	}

	return attrs
}

// GetBaseAttrHash calculates 16 bytes MD5 Hash of all available base attributes.
func (up *Update) GetBaseAttrHash() string {
	data, err := json.Marshal(&up.PathAttributes)
	if err != nil {
		data = []byte{0, 1, 0, 1, 0, 1, 0, 1}
	}
	s := fmt.Sprintf("%x", md5.Sum(data))

	return s
}

// GetNLRI29 check for presense of NLRI 29 in the update and if exists, instantiate NLRI29 object
func (up *Update) GetNLRI29() (*bgpls.NLRI, error) {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 29 {
			nlri29, err := bgpls.UnmarshalBGPLSNLRI(attr.Attribute)
			if err != nil {
				return nil, err
			}
			return nlri29, nil
		}
	}
	// TODO return new type of errors to be able to check for the code
	return nil, fmt.Errorf("not found")
}

// GetAttrPrefixSID check for presense of BGP Attribute Prefix SID (40) and instantiates it
func (up *Update) GetAttrPrefixSID() (*prefixsid.PSid, error) {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 40 {
			psid, err := prefixsid.UnmarshalBGPAttrPrefixSID(attr.Attribute)
			if err != nil {
				return nil, err
			}
			return psid, nil
		}
	}
	// TODO return new type of errors to be able to check for the code
	return nil, fmt.Errorf("not found")
}

// HasPrefixSID check for presense of BGP Attribute Prefix SID (40) and returns true is found
func (up *Update) HasPrefixSID() bool {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 40 {
			return true
		}
	}

	return false
}

func (up *Update) GetNLRIType() (uint8, int) {
	if len(up.PathAttributes) == 0 {
		// Fall back to default NLRI
		return BGP4_NLRI, 0
	}
	for i, p := range up.PathAttributes {
		switch p.AttributeType {
		case MP_REACH_NLRI:
			return MP_REACH_NLRI, i
		case MP_UNREACH_NLRI:
			return MP_UNREACH_NLRI, i
		}
	}

	return BGP4_NLRI, 0
}

// UnmarshalBGPUpdate build BGP Update object from the byte slice provided
func UnmarshalBGPUpdate(b []byte) (*Update, error) {
	if glog.V(6) {
		glog.Infof("BGPUpdate Raw: %s", tools.MessageHex(b))
	}
	p := 0
	u := Update{}
	u.WithdrawnRoutesLength = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	u.WithdrawnRoutes = make([]byte, u.WithdrawnRoutesLength)
	copy(u.WithdrawnRoutes, b[p:p+int(u.WithdrawnRoutesLength)])
	p += int(u.WithdrawnRoutesLength)
	u.TotalPathAttributeLength = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	attrs, err := UnmarshalBGPPathAttributes(b[p : p+int(u.TotalPathAttributeLength)])
	if err != nil {
		return nil, err
	}
	// Building BGP's update Base attributes struct which is common to all messages
	baseAttrs, err := UnmarshalBGPBaseAttributes(b[p : p+int(u.TotalPathAttributeLength)])
	if err != nil {
		return nil, err
	}
	u.PathAttributes = attrs
	u.BaseAttributes = baseAttrs
	p += int(u.TotalPathAttributeLength)
	u.NLRI = make([]byte, len(b)-p)
	copy(u.NLRI, b[p:])

	return &u, nil
}
