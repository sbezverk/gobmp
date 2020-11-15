package srpolicy

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// TLV defines a structure of sub tlv used to encode the
//   information about the SR Policy Candidate Path.
type TLV struct {
	Preference *Preference `json:"preference_subtlv,omitempty"`
	// BindingSID sub-TLV is used to signal the binding SID related
	// information of the SR Policy candidate path.  The contents of this
	// sub-TLV are used by the SRPM
	BindingSID  BSID           `json:"binding_sid_subtlv,omitempty"`
	Name        *PolicyName    `json:"policy_name_subtlv,omitempty"`
	PathName    *PathName      `json:"path_name_subtlv,omitempty"`
	Priority    *Priority      `json:"priority_subtlv,omitempty"`
	ENLP        *ENLP          `json:"enlp_subtlv,omitempty"`
	SegmentList []*SegmentList `json:"segment_list,omitempty"`
}

// UnmarshalSRPolicyTLV builds Link State NLRI object for SAFI 73
func UnmarshalSRPolicyTLV(b []byte) (*TLV, error) {
	if glog.V(5) {
		glog.Infof("SR Policy TLV Raw: %s", tools.MessageHex(b))
	}
	tlv := &TLV{}

	return tlv, nil
}
