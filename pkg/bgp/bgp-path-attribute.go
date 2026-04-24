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

// UnmarshalBGPPathAttributes builds a BGP Path attributes slice and populates
// BaseAttributes in a single pass over the byte buffer.
// Per RFC 4271 §4.3, TotalPathAttributeLength may be zero (pure withdrawal or
// End-of-RIB marker per RFC 4724 §2); in that case an empty but non-nil
// BaseAttributes is returned so callers can dereference it safely.
// AS_PATH width (2-byte vs 4-byte) is inferred by heuristic; use
// UnmarshalBGPPathAttributesWithAS4Hint when the caller has an authoritative
// indicator.
func UnmarshalBGPPathAttributes(b []byte) ([]PathAttribute, *BaseAttributes, error) {
	return unmarshalBGPPathAttributes(b, nil)
}

// UnmarshalBGPPathAttributesWithAS4Hint is UnmarshalBGPPathAttributes with an
// authoritative 4-byte-ASN indicator (typically PeerHeader.Is4ByteASN() per
// RFC 7854 §4.2, i.e. !A): true = 4-byte, false = 2-byte. Do not pass the
// raw A bit.
func UnmarshalBGPPathAttributesWithAS4Hint(b []byte, as4 bool) ([]PathAttribute, *BaseAttributes, error) {
	return unmarshalBGPPathAttributes(b, &as4)
}

func unmarshalBGPPathAttributes(b []byte, as4hint *bool) ([]PathAttribute, *BaseAttributes, error) {
	attrs, err := unmarshalRawPathAttributes(b)
	if err != nil {
		return nil, nil, err
	}
	baseAttrs, err := unmarshalBaseAttrsFromSlice(attrs, as4hint)
	if err != nil {
		return nil, nil, err
	}
	return attrs, baseAttrs, nil
}

// unmarshalRawPathAttributes decodes the TLV-encoded path attributes from a
// raw byte buffer into a []PathAttribute slice without any semantic
// interpretation. This is the low-level parser used by both
// UnmarshalBGPPathAttributes (top-level UPDATE) and UnmarshalAttrSet (embedded
// attributes inside ATTR_SET) so that forbidden-type checks can run before
// semantic mapping triggers recursion.
func unmarshalRawPathAttributes(b []byte) ([]PathAttribute, error) {
	if glog.V(6) {
		glog.Infof("BGPPathAttributes Raw: %s", tools.MessageHex(b))
	}
	attrs := make([]PathAttribute, 0, 8)

	for p := 0; p < len(b); {
		// Need at least flag + type (2 bytes) before reading anything.
		if p+2 > len(b) {
			return nil, fmt.Errorf("truncated path attribute header at offset %d: need 2 bytes, have %d", p, len(b)-p)
		}
		f := b[p]
		t := b[p+1]
		p += 2
		var l uint16
		// Checking for Extended-Length flag (bit 4 of flags).
		if f&0x10 == 0x10 {
			if p+2 > len(b) {
				return nil, fmt.Errorf("truncated extended-length field at offset %d: need 2 bytes, have %d", p, len(b)-p)
			}
			l = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
		} else {
			if p+1 > len(b) {
				return nil, fmt.Errorf("truncated length field at offset %d: need 1 byte, have %d", p, len(b)-p)
			}
			l = uint16(b[p])
			p++
		}
		if p+int(l) > len(b) {
			return nil, fmt.Errorf("truncated path attribute value at offset %d: need %d bytes, have %d", p, l, len(b)-p)
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
