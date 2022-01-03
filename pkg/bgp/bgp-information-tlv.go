package bgp

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// InformationalTLV defines BGP informational TLV object
type InformationalTLV struct {
	Type   byte
	Length byte
	Value  []byte
}

// UnmarshalBGPTLV builds a slice of Informational TLVs
func UnmarshalBGPTLV(b []byte) ([]InformationalTLV, Capability, error) {
	if glog.V(6) {
		glog.Infof("BGPTLV Raw: %s", tools.MessageHex(b))
	}
	tlvs := make([]InformationalTLV, 0)
	caps := make(Capability)
	for p := 0; p < len(b); {
		t := b[p]
		p++
		l := b[p]
		p++
		// Check if informational TLV carries Capabilities
		if t == 2 {
			c, err := UnmarshalBGPCapability(b[p : p+int(l)])
			if err != nil {
				return nil, nil, err
			}
			copyCapabilitiyMap(c, caps)
			p += int(l)
			continue
		}
		// Other than Capabilities informational tlvs are stored as is
		v := make([]byte, l)
		copy(v, b[p:p+int(l)])
		tlvs = append(tlvs, InformationalTLV{
			Type:   t,
			Length: l,
			Value:  v,
		})
		p += int(l)
	}

	return tlvs, caps, nil
}

func copyCapabilitiyMap(s, d Capability) {
	for k, v := range s {
		src := make([]*capabilityData, len(v))
		copy(src, v)
		dst, ok := d[k]
		if !ok {
			dst = make([]*capabilityData, 0)
		}
		dst = append(dst, src...)
		d[k] = dst
	}
}
