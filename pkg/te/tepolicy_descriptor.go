package te

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PolicyDescriptor defines the TE Policy Descriptors TLVs which are used
// to describe the TE Policy being advertised by using BGP-LS TE Policy NLRI type
type PolicyDescriptor struct {
	TLV []*base.TLV
}

// UnmarshalPolicyDescriptor builds PolicyDescriptor object with a list of TLVs
func UnmarshalPolicyDescriptor(b []byte) (*PolicyDescriptor, error) {
	if glog.V(6) {
		glog.Infof("TE Policy Descriptor Raw: %s", tools.MessageHex(b))
	}
	tlvs := make([]*base.TLV, 0)
	p := 0
	for p < len(b) {
		tlv := &base.TLV{}
		if p+4 >= len(b) {
			return nil, fmt.Errorf("not enough bytes to process TE Policy Descriptor")
		}
		tlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		tlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+int(tlv.Length) > len(b) {
			return nil, fmt.Errorf("not enough bytes to process TE Policy Descriptor")
		}
		tlv.Value = make([]byte, tlv.Length)
		copy(tlv.Value, b[p:p+int(tlv.Length)])
		tlvs = append(tlvs, tlv)
		p += int(tlv.Length)
	}

	return &PolicyDescriptor{
		TLV: tlvs,
	}, nil
}
