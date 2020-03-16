package bgp

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// InformationalTLV defines BGP informational TLV object
type InformationalTLV struct {
	Type   byte
	Length byte
	Value  []byte
}

// UnmarshalBGPTLV builds a slice of Informational TLVs
func UnmarshalBGPTLV(b []byte) ([]InformationalTLV, error) {
	glog.V(6).Infof("BGPTLV Raw: %s", internal.MessageHex(b))
	tlvs := make([]InformationalTLV, 0)
	for p := 0; p < len(b); {
		t := b[p]
		l := b[p+1]
		v := b[p+2 : p+2+int(l)]
		tlvs = append(tlvs, InformationalTLV{
			Type:   t,
			Length: l,
			Value:  v,
		})
		p += 2 + int(l)
	}

	return tlvs, nil
}
