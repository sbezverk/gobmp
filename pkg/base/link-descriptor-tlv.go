package base

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LinkDescriptorTLV defines Link Descriptor TLVs object
// https://tools.ietf.org/html/rfc7752#section-3.2.2
type LinkDescriptorTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// UnmarshalLinkDescriptorTLV builds Link Descriptor TLVs object
func UnmarshalLinkDescriptorTLV(b []byte) ([]LinkDescriptorTLV, error) {
	glog.V(6).Infof("LinkDescriptorTLV Raw: %s", tools.MessageHex(b))
	ltlvs := make([]LinkDescriptorTLV, 0)
	for p := 0; p < len(b); {
		ltlv := LinkDescriptorTLV{}
		ltlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		ltlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		ltlv.Value = make([]byte, ltlv.Length)
		copy(ltlv.Value, b[p:p+int(ltlv.Length)])
		ltlvs = append(ltlvs, ltlv)
		p += int(ltlv.Length)
	}

	return ltlvs, nil
}
