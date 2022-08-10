package te

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// NLRI defines TE Policy NLRI onject
type NLRI struct {
	ProtocolID  base.ProtoID
	Identifier  []byte               `json:"domain_id,omitempty"`
	HeadEnd     *base.NodeDescriptor `json:"headend_node_descriptor,omitempty"`
	HeadEndHash string               `json:"headend_node_hash,omitempty"`
	Policy      *PolicyDescriptor    `json:"te_policy_descriptor,omitempty"`
}

// UnmarshalTEPolicyNLRI builds SRv6SIDNLRI NLRI object
func UnmarshalTEPolicyNLRI(b []byte) (*NLRI, error) {
	if glog.V(6) {
		glog.Infof("TE Policy NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	te := NLRI{}
	p := 0
	if p+1 >= len(b) {
		return nil, fmt.Errorf("not enough bytes to process TE Policy NLRI")
	}
	te.ProtocolID = base.ProtoID(b[p])
	switch te.ProtocolID {
	case base.RSVPTE:
	case base.SR:
	default:
		return nil, fmt.Errorf("unrecognized protocol ID %d in TE Policy NLRI", te.ProtocolID)
	}
	p++
	if p+8 >= len(b) {
		return nil, fmt.Errorf("not enough bytes to process TE Policy NLRI")
	}
	te.Identifier = make([]byte, 8)
	copy(te.Identifier, b[p:p+8])
	p += 8
	if p+4 >= len(b) {
		return nil, fmt.Errorf("not enough bytes to process TE Policy NLRI")
	}
	// Get Node Descriptor's length, skip Node Descriptor Type
	l := binary.BigEndian.Uint16(b[p+2 : p+4])
	if p+int(l) >= len(b) {
		return nil, fmt.Errorf("not enough bytes to process TE Policy NLRI")
	}
	he, err := base.UnmarshalNodeDescriptor(b[p : p+int(l)+4])
	if err != nil {
		return nil, err
	}
	// Since HeadEnd Node Descriptor MUST include 512 and 516 TLVs
	// TODO Add check and return error if these two TLVs are missing
	te.HeadEnd = he
	te.HeadEndHash = fmt.Sprintf("%x", md5.Sum(b[p:p+int(l)+4]))
	p += int(l)
	// TE Policy Descriptor consists of list of TLVs, minimal TLV length is 4 bytes
	if p+4 < len(b) {
		te.Policy, err = UnmarshalPolicyDescriptor(b[p:])
		if err != nil {
			return nil, err
		}
	}

	return &te, nil
}
