package base

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// NodeDescriptorSubTLV defines Node Descriptor Sub TLVs object
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorSubTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// UnmarshalNodeDescriptorSubTLV builds Node Descriptor Sub TLVs object
func UnmarshalNodeDescriptorSubTLV(b []byte) ([]NodeDescriptorSubTLV, error) {
	glog.V(6).Infof("NodeDescriptorSubTLV Raw: %s", tools.MessageHex(b))
	stlvs := make([]NodeDescriptorSubTLV, 0)
	for p := 0; p < len(b); {
		stlv := NodeDescriptorSubTLV{}
		stlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		stlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		stlv.Value = make([]byte, stlv.Length)
		copy(stlv.Value, b[p:p+int(stlv.Length)])
		stlvs = append(stlvs, stlv)
		p += int(stlv.Length)
	}

	return stlvs, nil
}
