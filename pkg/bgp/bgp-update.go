package bgp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
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

// GetAllAttributeID returns a slice of uint8 with all attribute type codes found in BGP Update
func (up *Update) GetAllAttributeID() []uint8 {
	attrs := make([]uint8, 0, len(up.PathAttributes))
	for _, attr := range up.PathAttributes {
		attrs = append(attrs, attr.AttributeType)
	}

	return attrs
}

// GetBaseAttrHash calculates 16 bytes MD5 Hash of all available base attributes.
func (up *Update) GetBaseAttrHash() string {
	h := md5.New()
	for _, attr := range up.PathAttributes {
		h.Write(attr.Attribute)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GetNLRI29 check for presence of NLRI 29 in the update and if exists, instantiate NLRI29 object
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
	return nil, NewAttributeNotFoundError(29, "BGP-LS")
}

// GetAttrPrefixSID check for presence of BGP Attribute Prefix SID (40) and instantiates it
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
	return nil, NewAttributeNotFoundError(40, "Prefix SID")
}

// HasPrefixSID check for presence of BGP Attribute Prefix SID (40) and returns true is found
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
	if p+2 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Withdrawn Routes Length: need 2 bytes, have %d", len(b)-p)
	}
	u.WithdrawnRoutesLength = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if p+int(u.WithdrawnRoutesLength) > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Withdrawn Routes: need %d bytes, have %d", u.WithdrawnRoutesLength, len(b)-p)
	}
	u.WithdrawnRoutes = make([]byte, u.WithdrawnRoutesLength)
	copy(u.WithdrawnRoutes, b[p:p+int(u.WithdrawnRoutesLength)])
	p += int(u.WithdrawnRoutesLength)
	if p+2 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Total Path Attribute Length: need 2 bytes, have %d", len(b)-p)
	}
	u.TotalPathAttributeLength = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if p+int(u.TotalPathAttributeLength) > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Path Attributes: need %d bytes, have %d", u.TotalPathAttributeLength, len(b)-p)
	}
	// Single pass: parse path attributes and populate base attributes simultaneously
	attrs, baseAttrs, err := UnmarshalBGPPathAttributes(b[p : p+int(u.TotalPathAttributeLength)])
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
