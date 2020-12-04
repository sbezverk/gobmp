package bgpls

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

type SRBindingSID struct {
	FlagD bool   `json:"d_flag"`
	FlagB bool   `json:"b_flag"`
	FlagU bool   `json:"u_flag"`
	FlagL bool   `json:"l_flag"`
	FlagF bool   `json:"f_flag"`
	BSID  []byte `json:"binding_sid,omitempty"`
	PSID  []byte `json:"provisioned_sid,omitempty"`
}

// UnmarshalSRBindingSID instantiates SRBindingSID object
func UnmarshalSRBindingSID(b []byte) (*SRBindingSID, error) {
	if glog.V(6) {
		glog.Infof("SR Binding SID TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 12 && len(b) != 36 {
		return nil, fmt.Errorf("invalid length %d to decode SR Binding SID TLV", len(b))
	}
	bsid := &SRBindingSID{}
	p := 0
	bsid.FlagD = b[p]&0x80 == 0x80
	bsid.FlagB = b[p]&0x40 == 0x40
	bsid.FlagU = b[p]&0x20 == 0x20
	bsid.FlagL = b[p]&0x10 == 0x10
	bsid.FlagF = b[p]&0x08 == 0x08
	p += 2
	// Skip reserved 2 bytes
	p += 2
	l := 0
	// TODO (sbezverk) the beahaviour for B FLag
	if bsid.FlagD {
		// BSID is ipv6 address
		bsid.BSID = make([]byte, 16)
		l = 16
	} else {
		// BSID is MPLS label
		bsid.BSID = make([]byte, 4)
		l = 4
	}
	if p+l > len(b) {
		return nil, fmt.Errorf("not enough bytes to decode SR Binding SID TLV")
	}
	copy(bsid.BSID, b[p:p+l])
	p += l
	if bsid.FlagU {
		// Flag U indicates the Provisioned BSID value is unavailable when set.
		return bsid, nil
	}
	if p+l > len(b) {
		return nil, fmt.Errorf("not enough bytes to decode SR Binding SID TLV")
	}
	switch l {
	case 4:
		bsid.PSID = make([]byte, 4)
	case 16:
		bsid.PSID = make([]byte, 16)
	}
	copy(bsid.PSID, b[p:p+l])

	return bsid, nil
}

// SRCandidatePathState defines the object which carries the operational status
// and attributes of the SR Policy at the CP level.
type SRCandidatePathState struct {
	Priority   uint8  `json:"priority"`
	FlagS      bool   `json:"s_flag"`
	FlagA      bool   `json:"a_flag"`
	FlagB      bool   `json:"b_flag"`
	FlagE      bool   `json:"e_flag"`
	FlagV      bool   `json:"v_flag"`
	FlagO      bool   `json:"o_flag"`
	FlagD      bool   `json:"d_flag"`
	FlagC      bool   `json:"c_flag"`
	FlagI      bool   `json:"i_flag"`
	FlagT      bool   `json:"t_flag"`
	Preference uint32 `json:"preference"`
}

//UnmarshalSRCandidatePathState instantiates SRCandidatePathState object
func UnmarshalSRCandidatePathState(b []byte) (*SRCandidatePathState, error) {
	if glog.V(6) {
		glog.Infof("SR Binding SID TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 8 {
		return nil, fmt.Errorf("invalid length %d to decode SR Candidate Path State TLV", len(b))
	}
	s := &SRCandidatePathState{}

	return s, nil
}
