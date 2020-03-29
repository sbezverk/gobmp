package bgp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// Update defines a structure of BGP Update message
type Update struct {
	WithdrawnRoutesLength uint16
	//	WithdrawnRoutes          WithdrawnRoutes
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
	//	s += internal.MessageHex(up.NLRI)
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
	//	jsonData = append(jsonData, internal.RawBytesToJSON(up.NLRI)...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalBGPUpdate build BGP Update object from the byte slice provided
func UnmarshalBGPUpdate(b []byte) (*Update, error) {
	glog.V(6).Infof("BGPUpdate Raw: %s", internal.MessageHex(b))

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
