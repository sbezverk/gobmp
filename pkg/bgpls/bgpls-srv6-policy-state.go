package bgpls

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

const (
	// BindingSIDType defines Binding SID  TLV type
	BindingSIDType = 1201
	// SRCandidatePathStateType defines SR Candidate Path State  TLV type
	SRCandidatePathStateType = 1202
	// SRCandidatePathNameType defines SR Candidate Path Name  TLV type
	SRCandidatePathNameType = 1203
	// SRCandidatePathConstraintsType defines SR Candidate Path Constraints TLV type
	SRCandidatePathConstraintsType = 1204
	// SRSegmentListType defines SR Segment List TLV type
	SRSegmentListType = 1205
	// SRSegmentType defines SR Affinity Constraint Sub TLV type
	SRSegmentType = 1206
	// SRSegmentListMetricType defines SR Segment List Metric Sub TLV type
	SRSegmentListMetricType = 1207
	// SRAffinityConstraintType defines SR Affinity Constraint Sub TLV type
	SRAffinityConstraintType = 1208
	// SRSRLGConstraintType defines SR SRLG Constraint Sub TLV type
	SRSRLGConstraintType = 1209
	// SRBandwidthConstraintType defines SR Bandwidth Constraint Sub TLV type
	SRBandwidthConstraintType = 1210
	// SRDisjointGroupConstraintType defines SR DisjointGroup Constraint Sub TLV type
	SRDisjointGroupConstraintType = 1211
)

// SRBindingSID defines the struct of SR Binding SID object
type SRBindingSID struct {
	FlagD bool `json:"d_flag"`
	FlagB bool `json:"b_flag"`
	FlagU bool `json:"u_flag"`
	FlagL bool `json:"l_flag"`
	FlagF bool `json:"f_flag"`
	BSID  SID  `json:"binding_sid,omitempty"`
	PSID  SID  `json:"provisioned_sid,omitempty"`
}

// UnmarshalSRBindingSID instantiates SR Binding SID object from a slice of bytes
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
	var err error
	// TODO (sbezverk) the beahaviour for B FLag
	if bsid.FlagD {
		// BSID is ipv6 address
		bsid.BSID, err = UnmarshalSRv6SID(b[p : p+16])
		if err != nil {
			return nil, err
		}
		l = 16
	} else {
		// BSID is MPLS label
		bsid.BSID, err = UnmarshalMPLSLabelSID(b[p : p+4])
		if err != nil {
			return nil, err
		}
		l = 4
	}
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
		bsid.PSID, err = UnmarshalMPLSLabelSID(b[p : p+4])
		if err != nil {
			return nil, err
		}
	case 16:
		bsid.PSID, err = UnmarshalSRv6SID(b[p : p+16])
		if err != nil {
			return nil, err
		}
	}

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

//UnmarshalSRCandidatePathState instantiates SR Candidate Path State object from a slice of bytes
func UnmarshalSRCandidatePathState(b []byte) (*SRCandidatePathState, error) {
	if glog.V(6) {
		glog.Infof("SR Candidate Path State TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 8 {
		return nil, fmt.Errorf("invalid length %d to decode SR Candidate Path State TLV", len(b))
	}
	s := &SRCandidatePathState{}
	p := 0
	s.Priority = b[p]
	p++
	// Skip reserved byte
	p++
	s.FlagS = b[p]&0x80 == 0x80
	s.FlagA = b[p]&0x40 == 0x40
	s.FlagB = b[p]&0x20 == 0x20
	s.FlagE = b[p]&0x10 == 0x10
	s.FlagV = b[p]&0x08 == 0x08
	s.FlagO = b[p]&0x04 == 0x04
	s.FlagD = b[p]&0x02 == 0x02
	s.FlagC = b[p]&0x01 == 0x01
	p++
	s.FlagI = b[p]&0x80 == 0x80
	s.FlagT = b[p]&0x40 == 0x40
	p++
	s.Preference = binary.BigEndian.Uint32(b[p : p+4])

	return s, nil
}

// SRCandidatePathName defines the object which carries the symbolic name associated with the candidate path.
type SRCandidatePathName struct {
	SymbolicName string `json:"symbolic_name"`
}

// UnmarshalSRCandidatePathName instantiates SR Candidate Path Name object from a slice of bytes
func UnmarshalSRCandidatePathName(b []byte) (*SRCandidatePathName, error) {
	if glog.V(6) {
		glog.Infof("SR Candidate Path Name TLV Raw: %s", tools.MessageHex(b))
	}
	s := &SRCandidatePathName{
		SymbolicName: string(b),
	}

	return s, nil
}

// SRCandidatePathConstraintsSubTLV defines interface for SR Candidate Path Constraints Sub TLVs
type SRCandidatePathConstraintsSubTLV interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

// SRCandidatePathConstraints defines the object which carries the constraints associated with the candidate path.
type SRCandidatePathConstraints struct {
	FlagD  bool                                        `json:"d_flag"`
	FlagP  bool                                        `json:"p_flag"`
	FlagU  bool                                        `json:"u_flag"`
	FlagA  bool                                        `json:"a_flag"`
	FlagT  bool                                        `json:"t_flag"`
	MTID   uint16                                      `json:"mtid"`
	Algo   uint8                                       `json:"algorithm"`
	SubTLV map[uint16]SRCandidatePathConstraintsSubTLV `json:"subtlv,omitempty"`
}

// UnmarshalSRCandidatePathConstraints instantiates SR Candidate Path Constraints object from a slice of bytes
func UnmarshalSRCandidatePathConstraints(b []byte) (*SRCandidatePathConstraints, error) {
	if glog.V(6) {
		glog.Infof("SR Candidate Path Constraints TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("invalid length %d to decode SR Candidate Path Constraints TLV", len(b))
	}
	s := &SRCandidatePathConstraints{}
	p := 0
	s.FlagD = b[p]&0x80 == 0x80
	s.FlagP = b[p]&0x40 == 0x40
	s.FlagU = b[p]&0x20 == 0x20
	s.FlagA = b[p]&0x10 == 0x10
	s.FlagT = b[p]&0x08 == 0x08
	p += 2
	// Skip resreved 2 bytes
	s.MTID = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	s.Algo = b[p]
	p++
	// Skip reserved 1 byte
	if p < len(b) {
		var err error
		s.SubTLV, err = UnmarshalSRCandidatePathConstraintsSubTLV(b[p:])
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

// UnmarshalSRCandidatePathConstraintsSubTLV unmarshals a map of SR Candidate Path Constraints Sub TLV from a slice of bytes
func UnmarshalSRCandidatePathConstraintsSubTLV(b []byte) (map[uint16]SRCandidatePathConstraintsSubTLV, error) {
	if glog.V(6) {
		glog.Infof("SR Candidate Path Constraints Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to decode SR Candidate Path Constraints Sub TLV")
	}
	s := make(map[uint16]SRCandidatePathConstraintsSubTLV)
	p := 0
	for p < len(b) {
		t := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		l := binary.BigEndian.Uint16(b[p : p+2])
		if p+int(l) > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode SR Candidate Path Constraints Sub TLV")
		}
		switch t {
		case SRAffinityConstraintType:
			stlv, err := UnmarshalSRAffinityConstraint(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			s[SRAffinityConstraintType] = stlv
		case SRSRLGConstraintType:
			stlv, err := UnmarshalSRSRLGConstraint(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			s[SRSRLGConstraintType] = stlv
		case SRBandwidthConstraintType:
			stlv, err := UnmarshalSRBandwidthConstraint(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			s[SRBandwidthConstraintType] = stlv
		case SRDisjointGroupConstraintType:
			stlv, err := UnmarshalSRDisjointGroupConstraint(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			s[SRDisjointGroupConstraintType] = stlv
		}
		p += int(l)
	}

	return s, nil
}

var _ SRCandidatePathConstraintsSubTLV = &SRAffinityConstraint{}

// SRAffinityConstraint defines an object which carries the affinity constraints [RFC2702] associated with the
// candidate path.  The affinity is expressed in terms of Extended Admin
// Group (EAG) as defined in [RFC7308].
type SRAffinityConstraint struct {
	ExclAnySize uint8  `json:"excl_any_size"`
	InclAnySize uint8  `json:"incl_any_size"`
	InclAllSize uint8  `json:"incl_all_size"`
	ExclAnyEAG  uint32 `json:"excl_any_eag,omitempty"`
	InclAnyEAG  uint32 `json:"incl_any_eag,omitempty"`
	InclAllEAG  uint32 `json:"incl_all_eag,omitempty"`
}

// UnmarshalSRAffinityConstraint instantiates SR Affinity Constraint object from a slice of bytes
func UnmarshalSRAffinityConstraint(b []byte) (*SRAffinityConstraint, error) {
	if glog.V(6) {
		glog.Infof("SR Affinity Constraint Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to decode SR Affinity Constraint Sub TLV")
	}
	p := 0
	s := &SRAffinityConstraint{}
	s.ExclAnySize = b[p]
	p++
	s.InclAnySize = b[p]
	p++
	s.InclAllSize = b[p]
	p++
	// Skip reserved byte
	p++
	if s.ExclAnySize != 0 {
		if p+4 > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode SR Affinity Constraint Sub TLV")
		}
		binary.BigEndian.PutUint32(b[p:p+4], s.ExclAnyEAG)
		p += 4
	}
	if s.InclAnySize != 0 {
		if p+4 > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode SR Affinity Constraint Sub TLV")
		}
		binary.BigEndian.PutUint32(b[p:p+4], s.InclAnyEAG)
		p += 4
	}
	if s.InclAllSize != 0 {
		if p+4 > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode SR Affinity Constraint Sub TLV")
		}
		binary.BigEndian.PutUint32(b[p:p+4], s.InclAllEAG)
		p += 4
	}

	return s, nil
}

// MarshalJSON serializes SRAffinityConstraint into a slice of bytes
func (a *SRAffinityConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ExclAnySize uint8  `json:"excl_any_size"`
		InclAnySize uint8  `json:"incl_any_size"`
		InclAllSize uint8  `json:"incl_all_size"`
		ExclAnyEAG  uint32 `json:"excl_any_eag,omitempty"`
		InclAnyEAG  uint32 `json:"incl_any_eag,omitempty"`
		InclAllEAG  uint32 `json:"incl_all_eag,omitempty"`
	}{
		ExclAnySize: a.ExclAnySize,
		InclAnySize: a.InclAnySize,
		InclAllSize: a.InclAllSize,
		ExclAnyEAG:  a.ExclAnyEAG,
		InclAnyEAG:  a.InclAllEAG,
		InclAllEAG:  a.InclAllEAG,
	})
}

// UnmarshalJSON instantiates SRAffinityConstraint object from  a slice of bytes
func (a *SRAffinityConstraint) UnmarshalJSON(b []byte) error {
	t := &SRAffinityConstraint{}
	if err := json.Unmarshal(b, t); err != nil {
		return err
	}
	*a = *t

	return nil
}

var _ SRCandidatePathConstraintsSubTLV = &SRSRLGConstraint{}

// SRSRLGConstraint defines an object which carries the Shared Risk Link Group (SRLG) values [RFC4202] that are to
// be excluded from the candidate path.
type SRSRLGConstraint struct {
	SRLG []uint32 `json:"srlg"`
}

// UnmarshalSRSRLGConstraint instantiates SR SRLG Constraint object from a slice of bytes
func UnmarshalSRSRLGConstraint(b []byte) (*SRSRLGConstraint, error) {
	if glog.V(6) {
		glog.Infof("SR SRLG Constraint Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to decode SR SRLG Constraint Sub TLV")
	}
	n := len(b) % 4
	if n != 0 {
		return nil, fmt.Errorf("invalid length of SR SRLG Constraint Sub TLV")
	}
	s := &SRSRLGConstraint{
		SRLG: make([]uint32, n),
	}
	for p := 0; p < n; p++ {
		s.SRLG[p] = binary.BigEndian.Uint32(b[p*4 : p*4+4])
	}

	return s, nil
}

// MarshalJSON serializes SRSRLGConstraint into a slice of bytes
func (s *SRSRLGConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SRLG []uint32 `json:"srlg"`
	}{
		SRLG: s.SRLG,
	})
}

// UnmarshalJSON instantiates SRSRLGConstraint object from  a slice of bytes
func (s *SRSRLGConstraint) UnmarshalJSON(b []byte) error {
	t := &SRSRLGConstraint{}
	if err := json.Unmarshal(b, t); err != nil {
		return err
	}
	*s = *t

	return nil
}

var _ SRCandidatePathConstraintsSubTLV = &SRBandwidthConstraint{}

// SRBandwidthConstraint defines an object which indicates the desired bandwidth availability that needs to be
// ensured for the candidate path.
type SRBandwidthConstraint struct {
	Bandwidth uint32 `json:"bandwidth"`
}

// UnmarshalSRBandwidthConstraint instantiates SR Bandwidth Constraint object from a slice of bytes
func UnmarshalSRBandwidthConstraint(b []byte) (*SRBandwidthConstraint, error) {
	if glog.V(6) {
		glog.Infof("SR Bandwidth Constraint Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 4 {
		return nil, fmt.Errorf("not enough bytes to decode SR Bandwidth Constraint Sub TLV")
	}
	p := 0
	s := &SRBandwidthConstraint{}
	s.Bandwidth = binary.BigEndian.Uint32(b[p : p+4])
	return s, nil
}

// MarshalJSON serializes SRBandwidthConstraint into a slice of bytes
func (w *SRBandwidthConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Bandwidth uint32 `json:"bandwidth"`
	}{
		Bandwidth: w.Bandwidth,
	})
}

// UnmarshalJSON instantiates SRBandwidthConstraint object from  a slice of bytes
func (w *SRBandwidthConstraint) UnmarshalJSON(b []byte) error {
	t := &SRBandwidthConstraint{}
	if err := json.Unmarshal(b, t); err != nil {
		return err
	}
	*w = *t

	return nil
}

var _ SRCandidatePathConstraintsSubTLV = &SRDisjointGroupConstraint{}

// SRDisjointGroupConstraint defines an object which indicates DisjointGroup associated with the candidate path.
type SRDisjointGroupConstraint struct {
	RequestFlagS    bool   `json:"s_request_flag"`
	RequestFlagN    bool   `json:"n_request_flag"`
	RequestFlagL    bool   `json:"l_request_flag"`
	RequestFlagF    bool   `json:"f_request_flag"`
	RequestFlagI    bool   `json:"i_request_flag"`
	StatusFlagS     bool   `json:"s_status_flag"`
	StatusFlagN     bool   `json:"n_status_flag"`
	StatusFlagL     bool   `json:"l_status_flag"`
	StatusFlagF     bool   `json:"f_status_flag"`
	StatusFlagI     bool   `json:"i_status_flag"`
	StatusFlagX     bool   `json:"x_status_flag"`
	DisjointGroupID uint32 `json:"disjoint_group_id"`
}

// UnmarshalSRDisjointGroupConstraint instantiates SR DisjointGroup Constraint object from a slice of bytes
func UnmarshalSRDisjointGroupConstraint(b []byte) (*SRDisjointGroupConstraint, error) {
	if glog.V(6) {
		glog.Infof("SR DisjointGroup Constraint Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 8 {
		return nil, fmt.Errorf("not enough bytes to decode SR DisjointGroup Constraint Sub TLV")
	}
	p := 0
	s := &SRDisjointGroupConstraint{}
	s.RequestFlagS = b[p]&0x80 == 0x80
	s.RequestFlagN = b[p]&0x40 == 0x40
	s.RequestFlagL = b[p]&0x20 == 0x20
	s.RequestFlagF = b[p]&0x10 == 0x10
	s.RequestFlagI = b[p]&0x08 == 0x08
	p++
	s.StatusFlagS = b[p]&0x80 == 0x80
	s.StatusFlagN = b[p]&0x40 == 0x40
	s.StatusFlagL = b[p]&0x20 == 0x20
	s.StatusFlagF = b[p]&0x10 == 0x10
	s.StatusFlagI = b[p]&0x08 == 0x08
	s.StatusFlagX = b[p]&0x04 == 0x04
	p++
	// Skip 2 reserved bytes
	p += 2
	s.DisjointGroupID = binary.BigEndian.Uint32(b[p : p+4])

	return s, nil
}

// MarshalJSON serializes SRDisjointGroupConstraint into a slice of bytes
func (d *SRDisjointGroupConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RequestFlagS    bool   `json:"s_request_flag"`
		RequestFlagN    bool   `json:"n_request_flag"`
		RequestFlagL    bool   `json:"l_request_flag"`
		RequestFlagF    bool   `json:"f_request_flag"`
		RequestFlagI    bool   `json:"i_request_flag"`
		StatusFlagS     bool   `json:"s_status_flag"`
		StatusFlagN     bool   `json:"n_status_flag"`
		StatusFlagL     bool   `json:"l_status_flag"`
		StatusFlagF     bool   `json:"f_status_flag"`
		StatusFlagI     bool   `json:"i_status_flag"`
		StatusFlagX     bool   `json:"x_status_flag"`
		DisjointGroupID uint32 `json:"disjoint_group_id"`
	}{
		RequestFlagS:    d.RequestFlagS,
		RequestFlagN:    d.RequestFlagN,
		RequestFlagL:    d.RequestFlagL,
		RequestFlagF:    d.RequestFlagF,
		RequestFlagI:    d.RequestFlagI,
		StatusFlagS:     d.StatusFlagN,
		StatusFlagN:     d.StatusFlagN,
		StatusFlagL:     d.StatusFlagF,
		StatusFlagF:     d.StatusFlagF,
		StatusFlagI:     d.StatusFlagI,
		StatusFlagX:     d.StatusFlagX,
		DisjointGroupID: d.DisjointGroupID,
	})
}

// UnmarshalJSON instantiates SRDisjointGroupConstraint object from  a slice of bytes
func (d *SRDisjointGroupConstraint) UnmarshalJSON(b []byte) error {
	t := &SRDisjointGroupConstraint{}
	if err := json.Unmarshal(b, t); err != nil {
		return err
	}
	*d = *t

	return nil
}

// SRSegmentListSubTLV defines interface for SR Segment List Sub TLVs
type SRSegmentListSubTLV interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

// SRSegmentList defines SR Segment List objects which reports the SID-List(s) of acandidate path.
type SRSegmentList struct {
	FlagD  bool                           `json:"d_flag"`
	FlagE  bool                           `json:"e_flag"`
	FlagC  bool                           `json:"c_flag"`
	FlagV  bool                           `json:"v_flag"`
	FlagR  bool                           `json:"r_flag"`
	FlagF  bool                           `json:"f_flag"`
	FlagA  bool                           `json:"a_flag"`
	FlagT  bool                           `json:"t_flag"`
	FlagM  bool                           `json:"m_flag"`
	MTID   uint16                         `json:"mtid"`
	Algo   uint8                          `json:"algo"`
	Weight uint32                         `json:"weight"`
	SubTLV map[uint16]SRSegmentListSubTLV `json:"subtlv,omitempty"`
}

// UnmarshalSRSegmentList instantiates SRSegmentList from a slice of bytes
func UnmarshalSRSegmentList(b []byte) (*SRSegmentList, error) {
	if glog.V(6) {
		glog.Infof("SR Segment List TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 12 {
		return nil, fmt.Errorf("not enough bytes to decode SR Segment List TLV")
	}
	s := &SRSegmentList{}
	p := 0
	p++
	s.FlagD = b[p]&0x80 == 0x80
	s.FlagE = b[p]&0x40 == 0x40
	s.FlagC = b[p]&0x20 == 0x20
	s.FlagV = b[p]&0x10 == 0x10
	s.FlagR = b[p]&0x08 == 0x08
	s.FlagF = b[p]&0x04 == 0x04
	s.FlagA = b[p]&0x02 == 0x02
	s.FlagT = b[p]&0x01 == 0x01
	p++
	s.FlagM = b[p]&0x80 == 0x80
	// Skip 2 reserved bytes
	p += 2
	s.MTID = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	s.Algo = b[p]
	p++
	// Skip 1 reserved byte
	p++
	s.Weight = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	if p+4 > len(b) {
		return s, nil
	}
	ss, err := UnmarshalSRSegmentListSubTLV(b[p:])
	if err != nil {
		return nil, err
	}
	s.SubTLV = ss

	return s, nil
}

// UnmarshalSRSegmentListSubTLV instantiates a map of SR Segment List Sub TLVs from a slice of bytes
func UnmarshalSRSegmentListSubTLV(b []byte) (map[uint16]SRSegmentListSubTLV, error) {
	if glog.V(6) {
		glog.Infof("SR Segment List Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to decode SR Segment List Sub TLV")
	}
	s := make(map[uint16]SRSegmentListSubTLV)
	p := 0
	for p < len(b) {
		t := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		l := binary.BigEndian.Uint16(b[p : p+2])
		if p+int(l) > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode SR Segment List Sub TLV")
		}
		switch t {
		case SRSegmentType:
			stlv, err := UnmarshalSRSegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			s[SRSegmentType] = stlv
		case SRSegmentListMetricType:
			stlv, err := UnmarshalSRSegmentListMetric(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			s[SRSegmentListMetricType] = stlv
		}
		p += int(l)
	}
	return s, nil
}

// SegmentType defines type of the SR Segment
type SegmentType uint8

const (
	// SegmentTypeInvalid   0    Invalid
	SegmentTypeInvalid SegmentType = iota
	// SegmentType1 defines type 1    SR-MPLS Label
	SegmentType1
	// SegmentType2 defines type 2    SRv6 SID as IPv6 address
	SegmentType2
	// SegmentType3 defines type 3    SR-MPLS Prefix SID as IPv4 Node Address
	SegmentType3
	// SegmentType4 defines type 4    SR-MPLS Prefix SID as IPv6 Node Global Address
	SegmentType4
	// SegmentType5 defines type 5    SR-MPLS Adjacency SID as IPv4 Node Address & Local Interface ID
	SegmentType5
	// SegmentType6 defines type 6    SR-MPLS Adjacency SID as IPv4 Local & Remote Interface Addresses
	SegmentType6
	// SegmentType7 defines type 7    SR-MPLS Adjacency SID as pair of IPv6 Global Address & Interface ID for Local & Remote nodes
	SegmentType7
	// SegmentType8 defines type 8    SR-MPLS Adjacency SID as pair of IPv6 Global Addresses for the Local & Remote Interface
	SegmentType8
	// SegmentType9 defines type 9    SRv6 END SID as IPv6 Node Global Address
	SegmentType9
	// SegmentType10 defines type 10  SRv6 END.X SID as pair of IPv6 Global Address & Interface ID for Local & Remote nodes
	SegmentType10
	// SegmentType11 defines type 11  SRv6 END.X SID as pair of IPv6 Global Addresses for the Local & Remote Interface
	SegmentType11
)

// SID defines methods common to two types of SIDs MPLS Label or IPv6 address
type SID interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
	Len() int
}

// MPLSLabelSID defines SID as MPLS Label
type MPLSLabelSID struct {
	Label uint32 `json:"label"`
	TC    uint8  `json:"tc"`
	S     bool   `json:"s"`
	TTL   uint8  `json:"ttl"`
}

// UnmarshalMPLSLabelSID instantiates MPLSLabelSID object from a slice of bytes
func UnmarshalMPLSLabelSID(b []byte) (SID, error) {
	if glog.V(6) {
		glog.Infof("MPLS Label SID Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 4 {
		return nil, fmt.Errorf("not enough bytes to decode MPLS Label SID")
	}
	p := 0
	label := binary.BigEndian.Uint32(b[p : p+4])
	sid := &MPLSLabelSID{
		Label: label >> 12,
		TC:    uint8(label & 0x00000e00 >> 9),
		S:     label&0x00000100 == 0x00000100,
		TTL:   uint8(label & 0x000000ff),
	}

	return sid, nil
}

// Len returns the length of SID object
func (sid *MPLSLabelSID) Len() int {
	return 4
}

// MarshalJSON serializes PLSLabelSID into a slice of bytes
func (sid *MPLSLabelSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Label uint32 `json:"label"`
		TC    uint8  `json:"tc"`
		S     bool   `json:"s"`
		TTL   uint8  `json:"ttl"`
	}{
		Label: sid.Label,
		TC:    sid.TC,
		S:     sid.S,
		TTL:   sid.TTL,
	})
}

// UnmarshalJSON instantiates PLSLabelSID object from  a slice of bytes
func (sid *MPLSLabelSID) UnmarshalJSON(b []byte) error {
	t := &MPLSLabelSID{}
	if err := json.Unmarshal(b, t); err != nil {
		return err
	}
	*sid = *t

	return nil
}

// SRv6SID defines SID as IPv6 address
type SRv6SID struct {
	SID []byte `json:"srv6_sid"`
}

// UnmarshalSRv6SID instantiates SRv6 SID object from a slice of bytes
func UnmarshalSRv6SID(b []byte) (SID, error) {
	if glog.V(6) {
		glog.Infof("SRv6 SID Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("not enough bytes to decode SRv6 SID")
	}
	sid := &SRv6SID{
		SID: make([]byte, 16),
	}
	copy(sid.SID, b)

	return sid, nil
}

// Len returns the length of SID object
func (sid *SRv6SID) Len() int {
	return 16
}

// MarshalJSON serializes SRv6SID into a slice of bytes
func (sid *SRv6SID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SID []byte `json:"srv6_sid"`
	}{
		SID: sid.SID,
	})
}

// UnmarshalJSON instantiates SRv6SID object from  a slice of bytes
func (sid *SRv6SID) UnmarshalJSON(b []byte) error {
	t := &SRv6SID{}
	if err := json.Unmarshal(b, t); err != nil {
		return err
	}
	*sid = *t

	return nil
}

// SegmentDescriptor defines methods common to all SR Segment Descriptor types
type SegmentDescriptor interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
	Len() int
}

var _ SegmentDescriptor = &SRType1Descriptor{}

// SRType1Descriptor defines a descriptor for Type 1 Segment
type SRType1Descriptor struct {
	Algorithm uint8 `json:"algorithm"`
}

// UnmarshalSRType1Descriptor instantiates SR DisjointGroup Constraint object from a slice of bytes
func UnmarshalSRType1Descriptor(b []byte) (SegmentDescriptor, error) {
	if glog.V(6) {
		glog.Infof("SR Type1 Descriptor Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 1 {
		return nil, fmt.Errorf("invalid length %d of SR Type1 Descriptor", len(b))
	}
	p := 0
	s := &SRType1Descriptor{
		Algorithm: b[p],
	}
	return s, nil
}

// Len returns the length of Segment Descriptor
func (d *SRType1Descriptor) Len() int {
	return 1
}

// MarshalJSON serializes SRType1Descriptor into a slice of bytes
func (d *SRType1Descriptor) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Algorithm uint8 `json:"algorithm"`
	}{
		Algorithm: d.Algorithm,
	})
}

// UnmarshalJSON instantiates SRType1Descriptor object from  a slice of bytes
func (d *SRType1Descriptor) UnmarshalJSON(b []byte) error {
	t := &SRType1Descriptor{}
	if err := json.Unmarshal(b, t); err != nil {
		return err
	}
	*d = *t

	return nil
}

// SRSegmentSubTLV defines methods common SR Segment Sub TLVs
type SRSegmentSubTLV interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

// UnmarshalSRSegmentSubTLV instantiates a map of SR Segment Sub TLVs from a slice of bytes
func UnmarshalSRSegmentSubTLV(b []byte) (map[uint16]SRSegmentSubTLV, error) {
	if glog.V(6) {
		glog.Infof("SR Segment Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to decode SR Segment List Sub TLV")
	}
	s := make(map[uint16]SRSegmentSubTLV)
	p := 0
	for p < len(b) {
		t := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		l := binary.BigEndian.Uint16(b[p : p+2])
		if p+int(l) > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode SR Segment Sub TLV")
		}
		// No Sub Sub TLVs currently defined
		switch t {
		}
		p += int(l)
	}
	return s, nil
}

// SRSegment describes a single segment in a SID-List.  One or more instances of this sub-TLV in an ordered
// manner constitute a SID-List for a SR Policy candidate path.
type SRSegment struct {
	Segment           SegmentType                `json:"segment_type"`
	FlagS             bool                       `json:"s_flag"`
	FlagE             bool                       `json:"e_flag"`
	FlagV             bool                       `json:"v_flag"`
	FlagR             bool                       `json:"r_flag"`
	FlagA             bool                       `json:"a_flag"`
	SID               SID                        `json:"sid"`
	SegmentDescriptor SegmentDescriptor          `json:"segment_descriptor,omitempty"`
	SubTLV            map[uint16]SRSegmentSubTLV `json:"subtlv,omitempty"`
}

var _ SRSegmentListSubTLV = &SRSegment{}

// UnmarshalSRSegment instantiates SR Segment Sub TLV object from a slice of bytes
func UnmarshalSRSegment(b []byte) (SRSegmentListSubTLV, error) {
	if glog.V(6) {
		glog.Infof("SR Segment Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to decode SR Segment Sub TLV")
	}
	s := &SRSegment{}
	p := 0
	// Getting flags first
	s.FlagS = b[p+2]&0x80 == 0x80
	s.FlagE = b[p+2]&0x40 == 0x40
	s.FlagV = b[p+2]&0x20 == 0x20
	s.FlagR = b[p+2]&0x10 == 0x10
	s.FlagA = b[p+2]&0x08 == 0x08
	t := SegmentType(b[p])
	var err error
	switch t {
	case SegmentType1:
		s.Segment = SegmentType1
		if s.FlagS {
			s.SID, err = UnmarshalMPLSLabelSID(b[p+4 : p+4+4])
			if err != nil {
				return nil, err
			}
		}
	case SegmentType2:
		s.Segment = SegmentType2
		if s.FlagS {
			s.SID, err = UnmarshalSRv6SID(b[p+4 : p+4+16])
			if err != nil {
				return nil, err
			}
		}
	case SegmentType3:
		fallthrough
	case SegmentType4:
		fallthrough
	case SegmentType5:
		fallthrough
	case SegmentType6:
		fallthrough
	case SegmentType7:
		fallthrough
	case SegmentType8:
		fallthrough
	case SegmentType9:
		fallthrough
	case SegmentType10:
		fallthrough
	case SegmentType11:
		return nil, fmt.Errorf("segment of type %d is not yet implemented", t)
	default:
		return nil, fmt.Errorf("unknown segment type %d", t)
	}
	// Adjust pointer by 4 bytes (Segment Type, Reserved and 2 bytes of Flags) + length of SID
	p += 4 + s.SID.Len()
	// Check if the descriptor flag is set, if true then process descriptor
	if s.FlagA {
		if p >= len(b) {
			return nil, fmt.Errorf("invalid condition, with Flag A set but no more bytes to decode")
		}
		switch t {
		case SegmentType1:
			fallthrough
		case SegmentType2:
			// Type 2 shares the same descriptor as Type 1
			if s.SegmentDescriptor, err = UnmarshalSRType1Descriptor(b[p:]); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("segment descriptor of type %d is not yet implemented", t)
		}
		if s.SegmentDescriptor == nil {
			return nil, fmt.Errorf("invalid condition, with Flag A set the descriptor cannot be nil")
		}
		p += s.SegmentDescriptor.Len()
	}
	if p == len(b) {
		// There is no optional Sub Sub TLVs
		return s, nil
	}
	if p+4 > len(b) {
		// If left less than 4 bytes (type 2 bytes and length 2 bytes)
		return nil, fmt.Errorf("not enough bytes to decode SR Segment Sub TLV")
	}
	if s.SubTLV, err = UnmarshalSRSegmentSubTLV(b[p:]); err != nil {
		return nil, err
	}

	return s, nil
}

// MarshalJSON serializes SRSegment into a slice of bytes
func (s *SRSegment) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Segment SegmentType `json:"segment_type"`
		FlagS   bool        `json:"s_flag"`
		FlagE   bool        `json:"e_flag"`
		FlagV   bool        `json:"v_flag"`
		FlagR   bool        `json:"r_flag"`
		FlagA   bool        `json:"a_flag"`
		SID     SID         `json:"sid"`
	}{})
}

// UnmarshalJSON instantiates SRSegment object from  a slice of bytes
func (s *SRSegment) UnmarshalJSON(b []byte) error {
	t := &SRSegment{}
	if err := json.Unmarshal(b, t); err != nil {
		return err
	}
	*s = *t

	return nil
}

// SRMetricType defines type for SR Metric Type
type SRMetricType uint8

const (
	// SRMetricIGP defines IGP Metric type 0
	SRMetricIGP SRMetricType = iota
	// SRMetricMinUnidirLinkDelay defines Min Unidirection Link delay Metric type 1
	SRMetricMinUnidirLinkDelay
	// SRMetricTE defines TE Metric type 2
	SRMetricTE
)

var _ SRSegmentListSubTLV = &SRSegmentListMetric{}

// SRSegmentListMetric defines the metric used for computation of the SID-List.
type SRSegmentListMetric struct {
	Metric SRMetricType `json:"metric_type"`
	FlagM  bool         `json:"m_flag"`
	FlagA  bool         `json:"a_flag"`
	FlagB  bool         `json:"b_flag"`
	FlagV  bool         `json:"v_flag"`
	Margin uint32       `json:"metric_margine"`
	Bound  uint32       `json:"metric_bound"`
	Value  uint32       `json:"metric_value"`
}

// UnmarshalSRSegmentListMetric instantiates SR DisjointGroup Constraint object from a slice of bytes
func UnmarshalSRSegmentListMetric(b []byte) (SRSegmentListSubTLV, error) {
	if glog.V(6) {
		glog.Infof("SR Segment List Metric Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("invalid length of SR Segment List Metric")
	}
	p := 0
	s := &SRSegmentListMetric{}
	s.Metric = SRMetricType(b[p])
	p++
	s.FlagM = b[p]&0x80 == 0x80
	s.FlagA = b[p]&0x40 == 0x40
	s.FlagB = b[p]&0x20 == 0x20
	s.FlagV = b[p]&0x10 == 0x10
	p++
	// Skip reserved 2 bytes
	p += 2
	s.Margin = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	s.Bound = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	s.Value = binary.BigEndian.Uint32(b[p : p+4])

	return s, nil
}

// MarshalJSON serializes SRSegmentListMetric into a slice of bytes
func (m *SRSegmentListMetric) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Metric SRMetricType `json:"metric_type"`
		FlagM  bool         `json:"m_flag"`
		FlagA  bool         `json:"a_flag"`
		FlagB  bool         `json:"b_flag"`
		FlagV  bool         `json:"v_flag"`
		Margin uint32       `json:"metric_margine"`
		Bound  uint32       `json:"metric_bound"`
		Value  uint32       `json:"metric_value"`
	}{
		Metric: m.Metric,
		FlagM:  m.FlagM,
		FlagA:  m.FlagA,
		FlagB:  m.FlagB,
		FlagV:  m.FlagV,
		Margin: m.Margin,
		Bound:  m.Bound,
		Value:  m.Value,
	})
}

// UnmarshalJSON instantiates SRSegmentListMetric object from  a slice of bytes
func (m *SRSegmentListMetric) UnmarshalJSON(b []byte) error {
	t := &SRSegmentListMetric{}
	if err := json.Unmarshal(b, t); err != nil {
		return err
	}
	*m = *t

	return nil
}
