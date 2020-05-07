package bgp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/prefixsid"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Update defines a structure of BGP Update message
type Update struct {
	WithdrawnRoutesLength    uint16
	WithdrawnRoutes          []base.Route
	TotalPathAttributeLength uint16
	PathAttributes           []PathAttribute
	NLRI                     []base.Route
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

// GetAttrOrigin returns the value of Origin attribute if it is defined, otherwise it returns nil
func (up *Update) GetAttrOrigin() *string {
	var o string
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 1 {
			switch attr.Attribute[0] {
			case 0:
				o = "igp"
			case 1:
				o = "egp"
			case 2:
				o = "incomplete"
			}
			return &o
		}
	}

	return nil
}

// GetAttrASPath returns a sequence of AS path segments
func (up *Update) GetAttrASPath() []uint32 {
	path := make([]uint32, 0)
	for _, attr := range up.PathAttributes {
		if attr.AttributeType != 2 {
			continue
		}
		for p := 0; p < len(attr.Attribute); {
			// Skipping type
			p++
			// Length of path segment in 2 bytes
			l := int(attr.Attribute[p])
			p++
			as4 := false
			if l*4 == len(attr.Attribute)-p {
				as4 = true
			}
			for i := 0; i < l && p < len(attr.Attribute); i++ {
				if as4 {
					as := binary.BigEndian.Uint32(attr.Attribute[p : p+4])
					p += 4
					path = append(path, as)
				} else {
					as := binary.BigEndian.Uint16(attr.Attribute[p : p+2])
					p += 2
					path = append(path, uint32(as))
				}

			}
		}
	}

	return path
}

// GetAttrNextHop returns the value of Next Hop attribute if it is defined, otherwise it returns nil
func (up *Update) GetAttrNextHop() []byte {
	var nh []byte
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 3 {
			nh = make([]byte, attr.AttributeLength)
			copy(nh, attr.Attribute)
			return nh
		}
	}

	return nh
}

// GetAttrMED returns the value of MED attribute if it is defined, otherwise it returns nil
func (up *Update) GetAttrMED() *uint32 {
	var med uint32
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 4 {
			med = binary.BigEndian.Uint32(attr.Attribute)
			return &med
		}
	}

	return nil
}

// GetAttrLocalPref returns the value of LOCAL_PREF attribute if it is defined, otherwise it returns nil
func (up *Update) GetAttrLocalPref() *uint32 {
	var lp uint32
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 5 {
			lp = binary.BigEndian.Uint32(attr.Attribute)
			return &lp
		}
	}

	return nil
}

// GetAttrAtomicAggregate returns 1 if ATOMIC_AGGREGATE exists, 0 if does not
func (up *Update) GetAttrAtomicAggregate() bool {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 6 {
			return true
		}
	}

	return false
}

// GetAttrAggregator returns the value of AGGREGATOR attribute if it is defined, otherwise it returns nil
func (up *Update) GetAttrAggregator() []byte {
	var agg []byte
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 7 {
			agg = make([]byte, attr.AttributeLength)
			copy(agg, attr.Attribute)
			return agg
		}
	}

	return agg
}

// GetAttrCommunity returns a slice of communities
func (up *Update) GetAttrCommunity() []uint32 {
	comm := make([]uint32, 0)
	for _, attr := range up.PathAttributes {
		if attr.AttributeType != 8 {
			continue
		}
		for p := 0; p < len(attr.Attribute); {
			c := binary.BigEndian.Uint32(attr.Attribute[p : p+4])
			p += 4
			comm = append(comm, c)
		}
	}

	return comm
}

// GetAttrCommunityString returns the string with comma separated communities.
func (up *Update) GetAttrCommunityString() string {
	var communities string
	cs := up.GetAttrCommunity()
	for i, c := range cs {
		communities += fmt.Sprintf("%d:%d", (0xffff0000&c)>>16, 0xffff&c)
		if i < len(cs)-1 {
			communities += ", "
		}
	}

	return communities
}

// GetAttrOriginatorID returns the value of ORIGINATOR_ID attribute if it is defined, otherwise it returns nil
func (up *Update) GetAttrOriginatorID() []byte {
	var id []byte
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 9 {
			id = make([]byte, attr.AttributeLength)
			copy(id, attr.Attribute)
			return id
		}
	}

	return id
}

// GetAttrClusterListID returns the value of CLUSTER_LIST attribute if it is defined, otherwise it returns nil
func (up *Update) GetAttrClusterListID() []byte {
	var l []byte
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 10 {
			l = make([]byte, attr.AttributeLength)
			copy(l, attr.Attribute)
			return l
		}
	}

	return l
}

// GetAttrExtCommunity returns a slice with all extended communities found in bgp update
func (up *Update) GetAttrExtCommunity() ([]ExtCommunity, error) {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 16 {
			return UnmarshalBGPExtCommunity(attr.Attribute)
		}
	}

	return nil, fmt.Errorf("not found")
}

// GetAttrLgCommunity returns a slice with all large communities found in bgp update
func (up *Update) GetAttrLgCommunity() ([]LgCommunity, error) {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 32 {
			return UnmarshalBGPLgCommunity(attr.Attribute)
		}
	}

	return nil, fmt.Errorf("not found")
}

// GetExtCommunityRT returns  a slice of Route Target EXTENDED_COMMUNITY
func (up *Update) GetExtCommunityRT() ([]ExtCommunity, error) {
	rts := make([]ExtCommunity, 0)
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 16 {
			all, err := UnmarshalBGPExtCommunity(attr.Attribute)
			if err != nil {
				return nil, err
			}
			for _, c := range all {
				if c.IsRouteTarget() {
					rts = append(rts, c)
				}
			}
			return rts, nil
		}
	}

	return nil, fmt.Errorf("not found")
}

// GetAttrAS4Path returns a sequence of AS4 path segments
func (up *Update) GetAttrAS4Path() []uint32 {
	path := make([]uint32, 0)
	for _, attr := range up.PathAttributes {
		if attr.AttributeType != 17 {
			continue
		}
		for p := 0; p < len(attr.Attribute); {
			// Skipping type
			p++
			// Length of path segment in 4 bytes
			l := attr.Attribute[p]
			p++
			for n := 0; n < int(l); n++ {
				as := binary.BigEndian.Uint32(attr.Attribute[p : p+4])
				p += 4
				path = append(path, as)
			}
		}
	}

	return path
}

// GetAttrAS4Aggregator returns the value of AS4 AGGREGATOR attribute if it is defined, otherwise it returns nil
func (up *Update) GetAttrAS4Aggregator() []byte {
	var agg []byte
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 18 {
			agg = make([]byte, attr.AttributeLength)
			copy(agg, attr.Attribute)
			return agg
		}
	}

	return agg
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

// UnmarshalBGPUpdate build BGP Update object from the byte slice provided
func UnmarshalBGPUpdate(b []byte) (*Update, error) {
	glog.V(6).Infof("BGPUpdate Raw: %s", tools.MessageHex(b))

	p := 0
	u := Update{}
	u.WithdrawnRoutesLength = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	wdr, err := base.UnmarshalRoutes(b[p : p+int(u.WithdrawnRoutesLength)])
	if err != nil {
		return nil, err
	}
	u.WithdrawnRoutes = wdr
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
	routes, err := base.UnmarshalRoutes(b[p:])
	if err != nil {
		return nil, err
	}
	u.NLRI = routes

	return &u, nil
}
