package bgp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Update defines a structure of BGP Update message
type Update struct {
	WithdrawnRoutesLength    uint16
	WithdrawnRoutes          []Route
	TotalPathAttributeLength uint16
	PathAttributes           []PathAttribute
	NLRI                     []Route
}

func (up *Update) String() string {
	var s string
	s += fmt.Sprintf("Withdrawn Routes Length: %d\n", up.WithdrawnRoutesLength)
	if up.WithdrawnRoutesLength != 0 {
		for _, wr := range up.WithdrawnRoutes {
			s += wr.String()
		}
	}
	s += fmt.Sprintf("Total Path Attribute Length: %d\n", up.TotalPathAttributeLength)
	if up.TotalPathAttributeLength != 0 {
		for _, pa := range up.PathAttributes {
			s += pa.String()
		}
	}
	s += "NLRI: "
	// TODO fix it
	//	s += tools.MessageHex(up.NLRI)
	s += "\n"

	return s
}

// MarshalJSON defines a custom method to convert BGP Update object into JSON object
func (up *Update) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, []byte("{\"WithdrawnRoutesLength\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", up.WithdrawnRoutesLength))...)
	jsonData = append(jsonData, []byte("\"WithdrawnRoutes\":")...)
	//	jsonData = append(jsonData, []byte("{\"WithdrawnRoutes\":")...)
	jsonData = append(jsonData, '[')
	for i, wr := range up.WithdrawnRoutes {
		b, err := json.Marshal(&wr)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
		if i < len(up.WithdrawnRoutes)-1 {
			jsonData = append(jsonData, ',')
		}
	}
	jsonData = append(jsonData, []byte("],")...)

	jsonData = append(jsonData, []byte("\"TotalPathAttributeLength\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", up.TotalPathAttributeLength))...)

	jsonData = append(jsonData, []byte("\"PathAttributes\":")...)
	jsonData = append(jsonData, '[')
	for i, pa := range up.PathAttributes {
		b, err := json.Marshal(&pa)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
		if i < len(up.PathAttributes)-1 {
			jsonData = append(jsonData, ',')
		}
	}
	jsonData = append(jsonData, []byte("],")...)
	// TODO Fix it
	jsonData = append(jsonData, []byte("\"NLRI\":{}")...)
	// TODO Fix it
	//	jsonData = append(jsonData, tools.RawBytesToJSON(up.NLRI)...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
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
func (up *Update) GetAttrOrigin() *uint8 {
	var o uint8
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 1 {
			o = attr.Attribute[0]
			return &o
		}
	}

	return nil
}

// GetAttrASPath returns a sequence of AS path segments
func (up *Update) GetAttrASPath() []uint16 {
	path := make([]uint16, 0)
	for _, attr := range up.PathAttributes {
		if attr.AttributeType != 2 {
			continue
		}
		for p := 0; p < len(attr.Attribute); {
			// Skipping type
			p++
			// Length of path segment in 2 bytes
			l := attr.Attribute[p]
			p++
			for n := 0; n < int(l); n++ {
				as := binary.BigEndian.Uint16(attr.Attribute[p : p+2])
				p += 2
				path = append(path, as)
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
func (up *Update) GetAttrAtomicAggregate() uint8 {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 6 {
			return 1
		}
	}

	return 0
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

// UnmarshalBGPUpdate build BGP Update object from the byte slice provided
func UnmarshalBGPUpdate(b []byte) (*Update, error) {
	glog.V(6).Infof("BGPUpdate Raw: %s", tools.MessageHex(b))

	p := 0
	u := Update{}
	u.WithdrawnRoutesLength = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	wdr, err := UnmarshalBGPRoutes(b[p : p+int(u.WithdrawnRoutesLength)])
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
	u.PathAttributes = attrs
	p += int(u.TotalPathAttributeLength)
	routes, err := UnmarshalBGPRoutes(b[p:len(b)])
	if err != nil {
		return nil, err
	}
	u.NLRI = routes

	return &u, nil
}
