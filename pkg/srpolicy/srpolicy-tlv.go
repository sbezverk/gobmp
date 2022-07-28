package srpolicy

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// TLV defines a structure of sub tlv used to encode the
//   information about the SR Policy Candidate Path.
type TLV struct {
	Preference *Preference `json:"preference_subtlv,omitempty"`
	// BindingSID sub-TLV is used to signal the binding SID related
	// information of the SR Policy candidate path.  The contents of this
	// sub-TLV are used by the SRPM
	BindingSID *BindingSID `json:"binding_sid_subtlv,omitempty"`
	//PolicyName is a sub-TLV to associate a symbolic
	// name with the SR Policy for which the candidate path is being
	// advertised via the SR Policy NLRI.
	Name string `json:"policy_name_subtlv,omitempty"`
	// PathName is used to attach a symbolic name to the SR Policy candidate path.
	PathName string `json:"path_name_subtlv,omitempty"`
	// Priority indicate the order
	// in which the SR policies are re-computed upon topological change.
	Priority    byte           `json:"priority_subtlv,omitempty"`
	ENLP        *ENLP          `json:"enlp_subtlv,omitempty"`
	SegmentList []*SegmentList `json:"segment_list,omitempty"`
}

const (
	// SRPOLICYTUNNELTYPE defines Encapsulation Tunnel attribute value which is used by SR Policy to carry its STLVs
	SRPOLICYTUNNELTYPE = 15
	// WEIGHTSTLV defines Weight Sub TLV code
	WEIGHTSTLV = 9
	// SEGMENTLISTSTLV defines Segment List  Sub TLV code
	SEGMENTLISTSTLV = 128
	// BSIDSTLV defines Binding SID Sub TLV code
	BSIDSTLV = 13
	// SRV6STLV defines SRv6 Binding SID Sub TLV code (NOT YET DEFINED)
	SRV6STLV = 255
	// PREFERENCESTLV defines Preference Sub TLV code
	PREFERENCESTLV = 12
	// ENLPSTLV defines Explicit Null Label Policy Sub TLV code
	ENLPSTLV = 14
	// PRIORITYSTLV defines Priority Sub TLV code
	PRIORITYSTLV = 15
	// PATHNAMESTLV defines  Policy Candidate Path Name Sub-TLV code
	PATHNAMESTLV = 129
	// POLICYNAMESTLV defines Policy Name Sub-TLV Sub TLV code (NOT YET DEFINED)
	POLICYNAMESTLV = 254
)

// UnmarshalSRPolicyTLV builds Link State NLRI object for SAFI 73
func UnmarshalSRPolicyTLV(b []byte) (*TLV, error) {
	var err error
	if glog.V(5) {
		glog.Infof("SR Policy TLV Raw: %s", tools.MessageHex(b))
	}
	// In case of MP_UNREACH message, SR Policy does not carry any TLVs, so it is valid to have length of 0
	if len(b) == 0 {
		return nil, nil
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("invalid data length %d", len(b))
	}
	tlv := &TLV{
		SegmentList: make([]*SegmentList, 0),
	}
	p := 0
	t := binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if t != SRPOLICYTUNNELTYPE {
		return nil, fmt.Errorf("unexpected tunnel type %d", t)
	}
	l := binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if int(l)+p != len(b) {
		return nil, fmt.Errorf("encoded in data length: %d does not match with actual data length %d", int(l)+p, len(b))
	}
	for p < len(b) {
		st := b[p]
		sl := 0
		p++
		switch st {
		case SEGMENTLISTSTLV:
			glog.Infof("Segment List Sub TLV")
			sl = int(binary.BigEndian.Uint16(b[p : p+2]))
			p += 2
			// Skip reserved byte
			p++
			sl--
			l, err := UnmarshalSegmentListSTLV(b[p : p+sl])
			if err != nil {
				return nil, err
			}
			tlv.SegmentList = append(tlv.SegmentList, l)
		case BSIDSTLV:
			glog.Infof("Binding SID Sub TLV")
			sl = int(b[p])
			p++
			tlv.BindingSID = &BindingSID{}
			if tlv.BindingSID.BSID, err = UnmarshalBSIDSTLV(b[p : p+sl]); err != nil {
				return nil, err
			}
			tlv.BindingSID.Type = tlv.BindingSID.BSID.GetType()
		case PREFERENCESTLV:
			glog.Infof("Preference Sub TLV")
			sl = int(b[p])
			p++
			if tlv.Preference, err = UnmarshalPreferenceSTLV(b[p : p+sl]); err != nil {
				return nil, err
			}
		case ENLPSTLV:
			if tlv.ENLP != nil {
				return nil, fmt.Errorf("only 1 instance of ENLP allowed in SR Policy attributes")
			}
			glog.Infof("ENLP Sub TLV")
			sl = int(b[p])
			p++
			tlv.ENLP = &ENLP{
				Flags: b[p],
				ENLP:  b[p+2],
			}
		case PRIORITYSTLV:
			glog.Infof("Priority Sub TLV")
			sl = int(b[p])
			p++
			tlv.Priority = b[p]
		case PATHNAMESTLV:
			glog.Infof("Policy Candidate Path Name Sub TLV")
			sl = int(b[p])
			p++
			tlv.PathName = string(b[p : p+sl])
		default:
			glog.Warningf("SR Policy Sub TLV %+v is not supported", st)
			sl = int(b[p])
			p++
		}
		p += sl
	}
	return tlv, nil
}
