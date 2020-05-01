package base

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PrefixDescriptorTLV defines Prefix Descriptor Sub TLVs object
// https://tools.ietf.org/html/rfc7752#section-3.2.2
type PrefixDescriptorTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// UnmarshalPrefixDescriptorTLV builds Prefix Descriptor Sub TLVs object
func UnmarshalPrefixDescriptorTLV(b []byte) ([]PrefixDescriptorTLV, error) {
	glog.V(6).Infof("PrefixDescriptorTLV Raw: %s", tools.MessageHex(b))
	ptlvs := make([]PrefixDescriptorTLV, 0)
	for p := 0; p < len(b); {
		ptlv := PrefixDescriptorTLV{}
		ptlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		ptlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		ptlv.Value = make([]byte, ptlv.Length)
		copy(ptlv.Value, b[p:p+int(ptlv.Length)])
		p += int(ptlv.Length)
		ptlvs = append(ptlvs, ptlv)
	}

	return ptlvs, nil
}
