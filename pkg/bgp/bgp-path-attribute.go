package bgp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// PathAttribute defines a structure of an attribute
type PathAttribute struct {
	AttributeTypeFlags uint8
	AttributeType      uint8
	AttributeLength    uint16
	Attribute          []byte
}

func (pa *PathAttribute) String() string {
	var s string
	switch pa.AttributeType {
	case 0xe:
		// Found MP_REACH_NLRI attribute
		s += fmt.Sprintf("Attribute Type: %d (MP_REACH_NLRI)\n", pa.AttributeType)
		mp, err := UnmarshalMPReachNLRI(pa.Attribute)
		if err != nil {
			s += err.Error()
		} else {
			s += mp.String()
		}
	case 0x1d:
		s += fmt.Sprintf("Attribute Type: %d (BGP-LS)\n", pa.AttributeType)
		bgpls, err := bgpls.UnmarshalBGPLSNLRI(pa.Attribute)
		if err != nil {
			s += err.Error()
		} else {
			s += bgpls.String()
		}
	case 0xf:
		// Found MP_UNREACH_NLRI attribute
		s += fmt.Sprintf("Attribute Type: %d (MP_UNREACH_NLRI)\n", pa.AttributeType)
		s += internal.MessageHex(pa.Attribute)
		s += "\n"

	case 1:
		s += fmt.Sprintf("Attribute Type: %d (ORIGIN)\n", pa.AttributeType)
		s += fmt.Sprintf("   Origin: %d\n", pa.Attribute)
	case 2:
		s += fmt.Sprintf("Attribute Type: %d (AS_PATH)\n", pa.AttributeType)
		s += fmt.Sprintf("   AS PATH: %s\n", internal.MessageHex(pa.Attribute))
	case 5:
		s += fmt.Sprintf("Attribute Type: %d (LOCAL_PREF)\n", pa.AttributeType)
		s += fmt.Sprintf("   Local Pref: %d\n", binary.BigEndian.Uint32(pa.Attribute))
	default:
		s += fmt.Sprintf("Attribute Type: %d\n", pa.AttributeType)
		s += internal.MessageHex(pa.Attribute)
		s += "\n"
	}

	return s
}

// MarshalJSON defines a custom method to convert BGP Update object into JSON object
func (pa *PathAttribute) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, []byte("{\"AttributeTypeFlags\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", pa.AttributeTypeFlags))...)
	jsonData = append(jsonData, []byte("\"AttributeType\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", pa.AttributeType))...)
	jsonData = append(jsonData, []byte("\"AttributeLength\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", pa.AttributeLength))...)
	jsonData = append(jsonData, []byte("\"AttributeDescription\":")...)
	switch pa.AttributeType {
	case 0xe:
		// Found MP_REACH_NLRI attribute
		jsonData = append(jsonData, []byte("\"MP_REACH_NLRI\",")...)
		jsonData = append(jsonData, []byte("\"Attribute\":")...)
		mp, err := UnmarshalMPReachNLRI(pa.Attribute)
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(&mp)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	case 0x1d:
		jsonData = append(jsonData, []byte("\"BGP-LS\",")...)
		jsonData = append(jsonData, []byte("\"Attribute\":")...)
		mp, err := bgpls.UnmarshalBGPLSNLRI(pa.Attribute)
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(&mp)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	case 0xf:
		// Found MP_UNREACH_NLRI attribute
		jsonData = append(jsonData, []byte("\"MP_UNREACH_NLRI\",")...)
		jsonData = append(jsonData, []byte("\"Attribute\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(pa.Attribute)...)
	case 1:
		jsonData = append(jsonData, []byte("\"ORIGIN\",")...)
		jsonData = append(jsonData, []byte("\"Attribute\":")...)
		jsonData = append(jsonData, []byte(fmt.Sprintf("%d", pa.Attribute[0]))...)
	case 2:
		jsonData = append(jsonData, []byte("\"AS_PATH\",")...)
		jsonData = append(jsonData, []byte("\"Attribute\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(pa.Attribute)...)
	case 5:
		jsonData = append(jsonData, []byte("\"LOCAL_PREF\",")...)
		jsonData = append(jsonData, []byte("\"Attribute\":")...)
		jsonData = append(jsonData, []byte(fmt.Sprintf("%d", binary.BigEndian.Uint32(pa.Attribute)))...)
	default:
		jsonData = append(jsonData, []byte("\"Unknown\",")...)
		jsonData = append(jsonData, []byte("\"Attribute\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(pa.Attribute)...)
	}
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalBGPPathAttributes builds BGP Path attributes slice
func UnmarshalBGPPathAttributes(b []byte) ([]PathAttribute, error) {
	glog.V(6).Infof("BGPPathAttributes Raw: %s", internal.MessageHex(b))
	attrs := make([]PathAttribute, 0)

	for p := 0; p < len(b); {
		f := b[p]
		t := b[p+1]
		p += 2
		var l uint16
		// Checking for Extened
		if f&0x10 == 0x10 {
			l = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
		} else {
			l = uint16(b[p])
			p++
		}
		attrs = append(attrs, PathAttribute{
			AttributeTypeFlags: f,
			AttributeType:      t,
			AttributeLength:    l,
			Attribute:          b[p : p+int(l)],
		})
		p += int(l)
	}

	return attrs, nil
}
