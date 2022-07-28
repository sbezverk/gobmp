package te

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// PolicyDescriptor defines the TE Policy Descriptors TLVs which are used
// to describe the TE Policy being advertised by using BGP-LS TE Policy NLRI type
type PolicyDescriptor struct {
	TLV map[uint16]*base.TLV
}

// UnmarshalPolicyDescriptor builds PolicyDescriptor object with a list of TLVs
func UnmarshalPolicyDescriptor(b []byte) (*PolicyDescriptor, error) {
	if glog.V(6) {
		glog.Infof("TE Policy Descriptor Raw: %s", tools.MessageHex(b))
	}
	tlvs := make(map[uint16]*base.TLV)
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
		if _, ok := tlvs[tlv.Type]; ok {
			glog.Warningf("Found duplicate TLV of type %d in the list of TE Policy Descriptor's TLVs, please file an issue for gobmp", tlv.Type)
			glog.Infof("TE Policy Descriptor Raw: %s", tools.MessageHex(b))
			continue
		}
		tlvs[tlv.Type] = tlv
		p += int(tlv.Length)
	}

	return &PolicyDescriptor{
		TLV: tlvs,
	}, nil
}

// Exists returns true if specified as a parameter TLV ID exists in the list of Policy Descriptor TLVs,
// otherwise it returns false.
func (p *PolicyDescriptor) Exists(tlvType uint16) bool {
	_, ok := p.TLV[tlvType]
	return ok
}

// GetAllTLVIDs returns a slice of uint16 with all TLV ids found in an instance of PolicyDescriptor object
func (p *PolicyDescriptor) GetAllTLVIDs() []uint16 {
	ids := make([]uint16, len(p.TLV))
	i := 0
	for t := range p.TLV {
		ids[i] = t
		i++
	}

	return ids
}
