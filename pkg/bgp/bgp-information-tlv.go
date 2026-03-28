package bgp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// InformationalTLV defines BGP informational TLV object
type InformationalTLV struct {
	Type   byte
	Length uint16
	Value  []byte
}

// UnmarshalBGPTLV builds a slice of Informational TLVs from a standard BGP OPEN Optional Parameters
// field (RFC 4271: 1-byte parameter length). For RFC 9072 extended encoding use the caller in
// UnmarshalBGPOpenMessage which detects the sentinel and calls unmarshalTLVs directly.
func UnmarshalBGPTLV(b []byte) ([]InformationalTLV, Capability, error) {
	if glog.V(6) {
		glog.Infof("BGPTLV Raw: %s", tools.MessageHex(b))
	}
	return unmarshalTLVs(b, false)
}

// unmarshalTLVs is the shared implementation for both RFC 4271 (extendedParamLen=false, 1-byte
// parameter length) and RFC 9072 (extendedParamLen=true, 2-byte parameter length) encodings.
func unmarshalTLVs(b []byte, extendedParamLen bool) ([]InformationalTLV, Capability, error) {
	tlvs := make([]InformationalTLV, 0, 4)
	caps := make(Capability)
	if len(b) == 0 {
		return tlvs, caps, nil
	}
	for p := 0; p < len(b); {
		t := b[p]
		p++

		var l int
		if extendedParamLen {
			// RFC 9072: each Optional Parameter uses a 2-byte Length field.
			if p+2 > len(b) {
				return nil, nil, fmt.Errorf("truncated informational TLV length at offset %d: need 2 bytes, have %d", p, len(b)-p)
			}
			l = int(binary.BigEndian.Uint16(b[p : p+2]))
			p += 2
		} else {
			// RFC 4271: each Optional Parameter uses a 1-byte Length field.
			if p >= len(b) {
				return nil, nil, fmt.Errorf("truncated informational TLV length at offset %d: need 1 byte, have %d", p, len(b)-p)
			}
			l = int(b[p])
			p++
		}

		if p+l > len(b) {
			return nil, nil, fmt.Errorf("truncated informational TLV value at offset %d: need %d bytes, have %d", p, l, len(b)-p)
		}
		// Check if informational TLV carries Capabilities
		if t == 2 {
			c, err := UnmarshalBGPCapability(b[p : p+l])
			if err != nil {
				return nil, nil, err
			}
			copyCapabilityMap(c, caps)
			p += l
			continue
		}
		// Other than Capabilities informational TLVs are stored as-is.
		// Note: InformationalTLV.Length is uint16; in RFC 9072 mode individual parameter lengths
		// could theoretically exceed 255, but in practice capability values never do.
		v := make([]byte, l)
		copy(v, b[p:p+l])
		tlvs = append(tlvs, InformationalTLV{
			Type:   t,
			Length: uint16(l),
			Value:  v,
		})
		p += l
	}

	return tlvs, caps, nil
}

func copyCapabilityMap(s, d Capability) {
	for k, v := range s {
		src := make([]*CapabilityData, len(v))
		copy(src, v)
		dst, ok := d[k]
		if !ok {
			dst = make([]*CapabilityData, 0)
		}
		dst = append(dst, src...)
		d[k] = dst
	}
}
