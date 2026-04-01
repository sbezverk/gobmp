package bgp

import (
	"encoding/binary"
	"fmt"

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

// UnmarshalBGPPathAttributes builds BGP Path attributes slice and populates
// BaseAttributes in a single pass over the byte buffer.
// Per RFC 4271 §4.3, TotalPathAttributeLength may be zero (pure withdrawal or
// End-of-RIB marker per RFC 4724 §2); in that case an empty but non-nil
// BaseAttributes is returned so callers can dereference it safely.
func UnmarshalBGPPathAttributes(b []byte) ([]PathAttribute, *BaseAttributes, error) {
	if glog.V(6) {
		glog.Infof("BGPPathAttributes Raw: %s", tools.MessageHex(b))
	}
	attrs := make([]PathAttribute, 0, 8)

	for p := 0; p < len(b); {
		// Need at least flag + type (2 bytes) before reading anything.
		if p+2 > len(b) {
			return nil, nil, fmt.Errorf("truncated path attribute header at offset %d: need 2 bytes, have %d", p, len(b)-p)
		}
		f := b[p]
		t := b[p+1]
		p += 2
		var l uint16
		// Checking for Extended-Length flag (bit 4 of flags).
		if f&0x10 == 0x10 {
			if p+2 > len(b) {
				return nil, nil, fmt.Errorf("truncated extended-length field at offset %d: need 2 bytes, have %d", p, len(b)-p)
			}
			l = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
		} else {
			if p+1 > len(b) {
				return nil, nil, fmt.Errorf("truncated length field at offset %d: need 1 byte, have 0", p)
			}
			l = uint16(b[p])
			p++
		}
		if p+int(l) > len(b) {
			return nil, nil, fmt.Errorf("truncated path attribute value at offset %d: need %d bytes, have %d", p, l, len(b)-p)
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

	baseAttrs, err := unmarshalBaseAttrsFromSlice(attrs)
	if err != nil {
		return nil, nil, err
	}

	return attrs, baseAttrs, nil
}
