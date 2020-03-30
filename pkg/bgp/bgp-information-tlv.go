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
func UnmarshalBGPTLV(b []byte) ([]InformationalTLV, error) {
	glog.V(6).Infof("BGPTLV Raw: %s", tools.MessageHex(b))
	tlvs := make([]InformationalTLV, 0)
	for p := 0; p < len(b); {
		t := b[p]
		p++
		l := b[p]
		p++
		v := make([]byte, l)
		copy(v, b[p:p+int(l)])
		tlvs = append(tlvs, InformationalTLV{
			Type:   t,
			Length: l,
			Value:  v,
		})
		p += int(l)
	}

	return tlvs, nil
}
