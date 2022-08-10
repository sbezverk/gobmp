package bgp

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// PathAttribute defines a structure of an attribute
type PathAttribute struct {
	AttributeTypeFlags uint8
	AttributeType      uint8
	AttributeLength    uint16
	Attribute          []byte
}

// UnmarshalBGPPathAttributes builds BGP Path attributes slice
func UnmarshalBGPPathAttributes(b []byte) ([]PathAttribute, error) {
	if glog.V(6) {
		glog.Infof("BGPPathAttributes Raw: %s", tools.MessageHex(b))
	}
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
		pa := PathAttribute{
			AttributeTypeFlags: f,
			AttributeType:      t,
			AttributeLength:    l,
		}
		pa.Attribute = make([]byte, int(l))
		copy(pa.Attribute, b[p:p+int(l)])
		attrs = append(attrs, pa)

		p += int(l)
	}

	return attrs, nil
}
