package bgp

import (
	"encoding/binary"
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
	// s += fmt.Sprintf("Attribute Type Flags: 0x%02X\n", pa.AttributeTypeFlags)
	// s += fmt.Sprintf("Attribute Length: %d\n", pa.AttributeLength)
	switch pa.AttributeType {
	case 0xe:
		// Found MP_REACH_NLRI attribute
		s += fmt.Sprintf("Attribute Type: %d (MP_REACH_NLRI)\n", pa.AttributeType)
		mp, _ := UnmarshalMPReachNLRI(pa.Attribute)
		s += mp.String()
	case 0x1d:
		s += fmt.Sprintf("Attribute Type: %d (BGP-LS)\n", pa.AttributeType)
		bgpls, _ := bgpls.UnmarshalBGPLSNLRI(pa.Attribute)
		s += bgpls.String()
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

// UnmarshalBGPPathAttributes builds BGP Path attributes slice
func UnmarshalBGPPathAttributes(b []byte) ([]PathAttribute, error) {
	glog.V(6).Infof("BGPPathAttributes Raw: %s", internal.MessageHex(b))
	attrs := make([]PathAttribute, 0)

	for p := 0; p < len(b); {
		f := b[p]
		t := b[p+1]
		p += 2
		var l uint16
		// Chcking for Extened
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
