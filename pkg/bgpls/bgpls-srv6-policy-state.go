package bgpls

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/srv6"
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
	// SRv6BindingSIDType defines SRv6 Binding SID TLV type
	SRv6BindingSIDType = 1212
	// Type 1213: SR Policy Name TLV (Section 5.4).
	SRPolicyNameType = 1213
	// Type 1214: SR Bidirectional Group Constraint sub-TLV (Section 5.6.5).
	SRBidirectionalGroupConstraintType = 1214
	// Type 1215: SR Metric Constraint sub-TLV (Section 5.6.6).
	SRMetricConstraintType = 1215
	// Type 1216: SR Segment List Bandwidth sub-TLV (Section 5.7.3).
	SRSegmentListBandwidthType = 1216
	// Type 1217: SR Segment List Identifier sub-TLV (Section 5.7.4).
	SRSegmentListIdentifierType = 1217
)

// SRBindingSID defines the struct of SR Binding SID object
// TLV Type 1201 per draft-ietf-idr-bgp-ls-sr-policy-17
//
// Flags (per RFC 9256 section 6.2):
//   - FlagD (Dataplane): SRv6 (set) or SR-MPLS (clear)
//   - FlagB (Binding/Allocation): BSID allocated (set) or not allocated (clear)
//   - FlagU (Unavailable): Specified BSID unavailable (set) or in use (clear)
//   - FlagL (Local/SRLB): BSID from SRLB (set) or dynamic pool (clear)
//   - FlagF (Fallback): BSID allocated via fallback (set) or no fallback (clear)
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
	bsid := &SRBindingSID{}
	if len(b) != 12 && len(b) != 36 {
		return nil, fmt.Errorf("invalid length %d to decode SR Binding SID TLV", len(b))
	}
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
	// Per draft-ietf-idr-bgp-ls-sr-policy-17, the B-Flag indicates allocation status
	// (set = BSID allocated, clear = not allocated). It does not affect parsing logic
	// as both BSID and PSID fields are always present regardless of flag state.
	// The D-Flag determines field size: set = 16 octets (SRv6), clear = 4 octets (MPLS)
	if bsid.FlagD {
		// BSID is ipv6 address
		if len(b) != 36 {
			return nil, fmt.Errorf("invalid length %d to decode SR Binding SID TLV", len(b))
		}
		if p+16 > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode SR Binding SID TLV, need 16 bytes, have %d", len(b)-p)
		}
		bsid.BSID, err = UnmarshalSRv6SID(b[p : p+16])
		if err != nil {
			return nil, err
		}
		l = 16
	} else {
		// BSID is MPLS label
		if len(b) != 12 {
			return nil, fmt.Errorf("invalid length %d to decode SR Binding SID TLV", len(b))
		}
		bsid.BSID, err = UnmarshalMPLSLabelSID(b[p : p+4])
		if err != nil {
			return nil, err
		}
		l = 4
	}
	p += l
	if p+l > len(b) {
		return nil, fmt.Errorf("not enough bytes to decode SR Binding SID TLV, need %d bytes, have %d", l, len(b)-p)
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

//  0                   1
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |S|A|B|E|V|O|D|C|I|T|U|         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// SRCandidatePathState defines the object which carries the operational status
// and attributes of the SR Policy at the CP level.
// https://www.rfc-editor.org/info/rfc9857/#section-5.3
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
	FlagU      bool   `json:"u_flag"`
	Preference uint32 `json:"preference"`
}

// UnmarshalSRCandidatePathState instantiates SR Candidate Path State object from a slice of bytes
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
	s.FlagU = b[p]&0x20 == 0x20
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

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Type            |              Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Flags            |          RESERVED1            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             MTID              |   Algorithm   |   RESERVED2   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   sub-TLVs (variable)                                        //
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

//  0                   1
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |D|P|U|A|T|S|F|H|               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// SRCandidatePathConstraints defines the object which carries the constraints associated with the candidate path.
type SRCandidatePathConstraints struct {
	FlagD             bool                                        `json:"d_flag"`
	FlagP             bool                                        `json:"p_flag"`
	FlagU             bool                                        `json:"u_flag"`
	FlagA             bool                                        `json:"a_flag"`
	FlagT             bool                                        `json:"t_flag"`
	FlagS             bool                                        `json:"s_flag"`
	FlagF             bool                                        `json:"f_flag"`
	FlagH             bool                                        `json:"h_flag"`
	MTID              uint16                                      `json:"mtid"`
	Algo              uint8                                       `json:"algorithm"`
	SubTLV            map[uint16]SRCandidatePathConstraintsSubTLV `json:"subtlv,omitempty"`
	MetricConstraints []*SRMetricConstraint                       `json:"metric_constraints,omitempty"`
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
	s.FlagS = b[p]&0x04 == 0x04
	s.FlagF = b[p]&0x02 == 0x02
	s.FlagH = b[p]&0x01 == 0x01
	p += 2
	// Skip reserved 2 bytes
	p += 2
	s.MTID = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	s.Algo = b[p]
	p++
	// Skip 1 reserved byte
	p++
	if p < len(b) {
		var err error
		s.SubTLV, s.MetricConstraints, err = unmarshalSRCandidatePathConstraintsSubTLV(b[p:])
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

// UnmarshalSRCandidatePathConstraintsSubTLV unmarshals a map of SR Candidate Path Constraints Sub TLV from a slice of bytes
func UnmarshalSRCandidatePathConstraintsSubTLV(b []byte) (map[uint16]SRCandidatePathConstraintsSubTLV, error) {
	s, _, err := unmarshalSRCandidatePathConstraintsSubTLV(b)
	return s, err
}

func unmarshalSRCandidatePathConstraintsSubTLV(b []byte) (map[uint16]SRCandidatePathConstraintsSubTLV, []*SRMetricConstraint, error) {
	if glog.V(6) {
		glog.Infof("SR Candidate Path Constraints Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("not enough bytes to decode SR Candidate Path Constraints Sub TLV")
	}
	s := make(map[uint16]SRCandidatePathConstraintsSubTLV)
	var metrics []*SRMetricConstraint
	p := 0
	for p+4 <= len(b) {
		t := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+int(l) > len(b) {
			return nil, nil, fmt.Errorf("not enough bytes to decode SR Candidate Path Constraints Sub TLV")
		}
		switch t {
		case SRAffinityConstraintType:
			stlv, err := UnmarshalSRAffinityConstraint(b[p : p+int(l)])
			if err != nil {
				return nil, nil, err
			}
			s[SRAffinityConstraintType] = stlv
		case SRSRLGConstraintType:
			stlv, err := UnmarshalSRSRLGConstraint(b[p : p+int(l)])
			if err != nil {
				return nil, nil, err
			}
			s[SRSRLGConstraintType] = stlv
		case SRBandwidthConstraintType:
			stlv, err := UnmarshalSRBandwidthConstraint(b[p : p+int(l)])
			if err != nil {
				return nil, nil, err
			}
			s[SRBandwidthConstraintType] = stlv
		case SRDisjointGroupConstraintType:
			stlv, err := UnmarshalSRDisjointGroupConstraint(b[p : p+int(l)])
			if err != nil {
				return nil, nil, err
			}
			s[SRDisjointGroupConstraintType] = stlv
		case SRBidirectionalGroupConstraintType:
			stlv, err := UnmarshalSRBidirGroupConstrant(b[p : p+int(l)])
			if err != nil {
				return nil, nil, err
			}
			s[SRBidirectionalGroupConstraintType] = stlv
		case SRMetricConstraintType:
			stlv, err := UnmarshalSRMetricConstraint(b[p : p+int(l)])
			if err != nil {
				return nil, nil, err
			}
			s[SRMetricConstraintType] = stlv
			metrics = append(metrics, stlv)
		}
		p += int(l)
	}
	if p != len(b) {
		return nil, nil, fmt.Errorf("SR Candidate Path Constraints Sub TLV: %d trailing bytes", len(b)-p)
	}

	return s, metrics, nil
}

var _ SRCandidatePathConstraintsSubTLV = &SRAffinityConstraint{}

// SRAffinityConstraint defines an object which carries the affinity constraints [RFC2702] associated with the
// candidate path.  The affinity is expressed in terms of Extended Admin
// Group (EAG) as defined in [RFC7308].
type SRAffinityConstraint struct {
	ExclAnySize uint8    `json:"excl_any_size"`
	InclAnySize uint8    `json:"incl_any_size"`
	InclAllSize uint8    `json:"incl_all_size"`
	ExclAnyEAG  []uint32 `json:"excl_any_eag,omitempty"`
	InclAnyEAG  []uint32 `json:"incl_any_eag,omitempty"`
	InclAllEAG  []uint32 `json:"incl_all_eag,omitempty"`
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
	s.ExclAnyEAG = make([]uint32, 0, s.ExclAnySize)
	s.InclAnyEAG = make([]uint32, 0, s.InclAnySize)
	s.InclAllEAG = make([]uint32, 0, s.InclAllSize)
	expected := int(s.ExclAnySize)*4 +
		int(s.InclAnySize)*4 +
		int(s.InclAllSize)*4
	if len(b[p:]) != expected {
		return nil, fmt.Errorf("SR Affinity Constraint: expected %d bytes for ExclAnyEAG, InclAnyEAG and InclAllEAG, have %d", expected, len(b[p:]))
	}
	if s.ExclAnySize != 0 {
		for i := 0; i < int(s.ExclAnySize); i++ {
			if p+4 > len(b) {
				return nil, fmt.Errorf("not enough bytes to decode SR Affinity Constraint ExclAnySize, need 4 bytes, have %d", len(b)-p)
			}
			s.ExclAnyEAG = append(s.ExclAnyEAG, binary.BigEndian.Uint32(b[p:p+4]))
			p += 4
		}
	}
	if s.InclAnySize != 0 {
		for i := 0; i < int(s.InclAnySize); i++ {
			if p+4 > len(b) {
				return nil, fmt.Errorf("not enough bytes to decode SR Affinity Constraint InclAnySize, need 4 bytes, have %d", len(b)-p)
			}
			s.InclAnyEAG = append(s.InclAnyEAG, binary.BigEndian.Uint32(b[p:p+4]))
			p += 4
		}
	}
	if s.InclAllSize != 0 {
		for i := 0; i < int(s.InclAllSize); i++ {
			if p+4 > len(b) {
				return nil, fmt.Errorf("not enough bytes to decode SR Affinity Constraint InclAllSize, need 4 bytes, have %d", len(b)-p)
			}
			s.InclAllEAG = append(s.InclAllEAG, binary.BigEndian.Uint32(b[p:p+4]))
			p += 4
		}
	}

	if len(s.ExclAnyEAG) == 0 {
		s.ExclAnyEAG = nil
	}
	if len(s.InclAnyEAG) == 0 {
		s.InclAnyEAG = nil
	}
	if len(s.InclAllEAG) == 0 {
		s.InclAllEAG = nil
	}
	return s, nil
}

// MarshalJSON serializes SRAffinityConstraint into a slice of bytes
func (a *SRAffinityConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ExclAnySize uint8    `json:"excl_any_size"`
		InclAnySize uint8    `json:"incl_any_size"`
		InclAllSize uint8    `json:"incl_all_size"`
		ExclAnyEAG  []uint32 `json:"excl_any_eag,omitempty"`
		InclAnyEAG  []uint32 `json:"incl_any_eag,omitempty"`
		InclAllEAG  []uint32 `json:"incl_all_eag,omitempty"`
	}{
		ExclAnySize: a.ExclAnySize,
		InclAnySize: a.InclAnySize,
		InclAllSize: a.InclAllSize,
		ExclAnyEAG:  a.ExclAnyEAG,
		InclAnyEAG:  a.InclAnyEAG,
		InclAllEAG:  a.InclAllEAG,
	})
}

// UnmarshalJSON instantiates SRAffinityConstraint object from  a slice of bytes
func (a *SRAffinityConstraint) UnmarshalJSON(b []byte) error {
	t := struct {
		ExclAnySize uint8    `json:"excl_any_size"`
		InclAnySize uint8    `json:"incl_any_size"`
		InclAllSize uint8    `json:"incl_all_size"`
		ExclAnyEAG  []uint32 `json:"excl_any_eag,omitempty"`
		InclAnyEAG  []uint32 `json:"incl_any_eag,omitempty"`
		InclAllEAG  []uint32 `json:"incl_all_eag,omitempty"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	a.ExclAnySize = t.ExclAnySize
	a.InclAnySize = t.InclAnySize
	a.InclAllSize = t.InclAllSize
	a.ExclAnyEAG = t.ExclAnyEAG
	a.InclAnyEAG = t.InclAnyEAG
	a.InclAllEAG = t.InclAllEAG

	return nil
}

var _ SRCandidatePathConstraintsSubTLV = &SRSRLGConstraint{}

// SRSRLGConstraint defines an object which carries the Shared Risk Link Group (SRLG) values [RFC4202] that are to
// be excluded from the candidate path.
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
		return nil, fmt.Errorf("not enough bytes to decode SR SRLG Constraint Sub TLV, need at least 4 bytes, have %d", len(b))
	}
	n := len(b) % 4
	if n != 0 {
		return nil, fmt.Errorf("invalid length of SR SRLG Constraint Sub TLV, need multiple of 4 bytes, have %d", len(b))
	}
	s := &SRSRLGConstraint{
		SRLG: make([]uint32, len(b)/4),
	}
	for p := 0; p < len(b)/4; p++ {
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
	t := struct {
		SRLG []uint32 `json:"srlg"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	s.SRLG = t.SRLG

	return nil
}

var _ SRCandidatePathConstraintsSubTLV = &SRBandwidthConstraint{}

// SRBandwidthConstraint defines an object which indicates the desired bandwidth availability that needs to be
// ensured for the candidate path.
type SRBandwidthConstraint struct {
	Bandwidth float32 `json:"bandwidth"`
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
	s.Bandwidth = math.Float32frombits(binary.BigEndian.Uint32(b[p : p+4]))
	return s, nil
}

// MarshalJSON serializes SRBandwidthConstraint into a slice of bytes
func (w *SRBandwidthConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Bandwidth float32 `json:"bandwidth"`
	}{
		Bandwidth: float32(w.Bandwidth),
	})
}

// UnmarshalJSON instantiates SRBandwidthConstraint object from  a slice of bytes
func (w *SRBandwidthConstraint) UnmarshalJSON(b []byte) error {
	t := struct {
		Bandwidth float32 `json:"bandwidth"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	w.Bandwidth = float32(t.Bandwidth)

	return nil
}

var _ SRCandidatePathConstraintsSubTLV = &SRDisjointGroupConstraint{}

// https://www.rfc-editor.org/info/rfc9857/#section-5.6.4

// SRDisjointGroupConstraint defines an object which indicates DisjointGroup associated with the candidate path.
type SRDisjointGroupConstraint struct {
	//  0 1 2 3 4 5 6 7
	// +-+-+-+-+-+-+-+-+
	// |S|N|L|F|I|     |
	// +-+-+-+-+-+-+-+-+
	RequestFlagS bool `json:"s_request_flag"`
	RequestFlagN bool `json:"n_request_flag"`
	RequestFlagL bool `json:"l_request_flag"`
	RequestFlagF bool `json:"f_request_flag"`
	RequestFlagI bool `json:"i_request_flag"`
	// 	 0 1 2 3 4 5 6 7
	// +-+-+-+-+-+-+-+-+
	// |S|N|L|F|I|X|   |
	// +-+-+-+-+-+-+-+-+
	StatusFlagS        bool    `json:"s_status_flag"`
	StatusFlagN        bool    `json:"n_status_flag"`
	StatusFlagL        bool    `json:"l_status_flag"`
	StatusFlagF        bool    `json:"f_status_flag"`
	StatusFlagI        bool    `json:"i_status_flag"`
	StatusFlagX        bool    `json:"x_status_flag"`
	DisJointGroupID    *uint32 `json:"disjoint_group_id,omitempty"`
	PCEPAssociationObj []byte  `json:"pcep_association_obj,omitempty"`
}

// UnmarshalSRDisjointGroupConstraint instantiates SR DisjointGroup Constraint object from a slice of bytes
func UnmarshalSRDisjointGroupConstraint(b []byte) (*SRDisjointGroupConstraint, error) {
	if glog.V(6) {
		glog.Infof("SR DisjointGroup Constraint Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 8 {
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
	if p+4 == len(b) {
		v := binary.BigEndian.Uint32(b[p : p+4])
		s.DisJointGroupID = &v
	} else {
		s.PCEPAssociationObj = b[p:]
	}

	return s, nil
}

// MarshalJSON serializes SRDisjointGroupConstraint into a slice of bytes
func (d *SRDisjointGroupConstraint) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RequestFlagS       bool    `json:"s_request_flag"`
		RequestFlagN       bool    `json:"n_request_flag"`
		RequestFlagL       bool    `json:"l_request_flag"`
		RequestFlagF       bool    `json:"f_request_flag"`
		RequestFlagI       bool    `json:"i_request_flag"`
		StatusFlagS        bool    `json:"s_status_flag"`
		StatusFlagN        bool    `json:"n_status_flag"`
		StatusFlagL        bool    `json:"l_status_flag"`
		StatusFlagF        bool    `json:"f_status_flag"`
		StatusFlagI        bool    `json:"i_status_flag"`
		StatusFlagX        bool    `json:"x_status_flag"`
		DisJointGroupID    *uint32 `json:"disjoint_group_id,omitempty"`
		PCEPAssociationObj []byte  `json:"pcep_association_obj,omitempty"`
	}{
		RequestFlagS:       d.RequestFlagS,
		RequestFlagN:       d.RequestFlagN,
		RequestFlagL:       d.RequestFlagL,
		RequestFlagF:       d.RequestFlagF,
		RequestFlagI:       d.RequestFlagI,
		StatusFlagS:        d.StatusFlagS,
		StatusFlagN:        d.StatusFlagN,
		StatusFlagL:        d.StatusFlagL,
		StatusFlagF:        d.StatusFlagF,
		StatusFlagI:        d.StatusFlagI,
		StatusFlagX:        d.StatusFlagX,
		DisJointGroupID:    d.DisJointGroupID,
		PCEPAssociationObj: d.PCEPAssociationObj,
	})
}

// UnmarshalJSON instantiates SRDisjointGroupConstraint object from  a slice of bytes
func (d *SRDisjointGroupConstraint) UnmarshalJSON(b []byte) error {
	t := struct {
		RequestFlagS       bool    `json:"s_request_flag"`
		RequestFlagN       bool    `json:"n_request_flag"`
		RequestFlagL       bool    `json:"l_request_flag"`
		RequestFlagF       bool    `json:"f_request_flag"`
		RequestFlagI       bool    `json:"i_request_flag"`
		StatusFlagS        bool    `json:"s_status_flag"`
		StatusFlagN        bool    `json:"n_status_flag"`
		StatusFlagL        bool    `json:"l_status_flag"`
		StatusFlagF        bool    `json:"f_status_flag"`
		StatusFlagI        bool    `json:"i_status_flag"`
		StatusFlagX        bool    `json:"x_status_flag"`
		DisJointGroupID    *uint32 `json:"disjoint_group_id,omitempty"`
		PCEPAssociationObj []byte  `json:"pcep_association_obj,omitempty"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	d.RequestFlagS = t.RequestFlagS
	d.RequestFlagN = t.RequestFlagN
	d.RequestFlagL = t.RequestFlagL
	d.RequestFlagF = t.RequestFlagF
	d.RequestFlagI = t.RequestFlagI
	d.StatusFlagS = t.StatusFlagS
	d.StatusFlagN = t.StatusFlagN
	d.StatusFlagL = t.StatusFlagL
	d.StatusFlagF = t.StatusFlagF
	d.StatusFlagI = t.StatusFlagI
	d.StatusFlagX = t.StatusFlagX
	d.DisJointGroupID = t.DisJointGroupID
	d.PCEPAssociationObj = t.PCEPAssociationObj

	return nil
}

// SRSegmentListSubTLV defines interface for SR Segment List Sub TLVs
type SRSegmentListSubTLV interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

// SRSegmentList defines SR Segment List objects which reports the SID-List(s) of a candidate path.
type SRSegmentList struct {
	FlagD  bool                  `json:"d_flag"`
	FlagE  bool                  `json:"e_flag"`
	FlagC  bool                  `json:"c_flag"`
	FlagV  bool                  `json:"v_flag"`
	FlagR  bool                  `json:"r_flag"`
	FlagF  bool                  `json:"f_flag"`
	FlagA  bool                  `json:"a_flag"`
	FlagT  bool                  `json:"t_flag"`
	FlagM  bool                  `json:"m_flag"`
	MTID   uint16                `json:"mtid"`
	Algo   uint8                 `json:"algo"`
	Weight uint32                `json:"weight"`
	SubTLV []SRSegmentListSubTLV `json:"subtlv,omitempty"`
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

// UnmarshalSRSegmentListSubTLV instantiates a slice of SR Segment List Sub TLVs from a slice of bytes.
// Multiple SRSegment sub-TLVs (type 1206) are valid per RFC 9256 §2.4.4 — each is appended in order.
func UnmarshalSRSegmentListSubTLV(b []byte) ([]SRSegmentListSubTLV, error) {
	if glog.V(6) {
		glog.Infof("SR Segment List Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to decode SR Segment List Sub TLV, need at least 4 bytes, have %d", len(b))
	}
	s := make([]SRSegmentListSubTLV, 0)
	p := 0
	for p+4 <= len(b) {
		t := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+int(l) > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode SR Segment List Sub TLV value at offset %d, need %d bytes, have %d", p, l, len(b)-p)
		}
		switch t {
		case SRSegmentType:
			stlv, err := UnmarshalSRSegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			s = append(s, stlv)
		case SRSegmentListMetricType:
			stlv, err := UnmarshalSRSegmentListMetric(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			s = append(s, stlv)
		case SRSegmentListBandwidthType:
			stlv, err := UnmarshalSRSegmentListBandwidth(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			s = append(s, stlv)
		case SRSegmentListIdentifierType:
			stlv, err := UnmarshalSRSegmentListIdentifier(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			s = append(s, stlv)
		}
		p += int(l)
	}
	if p != len(b) {
		return nil, fmt.Errorf("SR Segment List Sub TLV: %d trailing bytes", len(b)-p)
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
	t := struct {
		Label uint32 `json:"label"`
		TC    uint8  `json:"tc"`
		S     bool   `json:"s"`
		TTL   uint8  `json:"ttl"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	sid.Label = t.Label
	sid.TC = t.TC
	sid.S = t.S
	sid.TTL = t.TTL

	return nil
}

// SRv6SID defines SID as IPv6 address
type SRv6SID struct {
	SID []byte `json:"srv6_sid"`
}

func (sid *SRv6SID) MarshalJSON() ([]byte, error) {
	if sid == nil {
		return nil, fmt.Errorf("SRv6 SID is nil")
	}
	if len(sid.SID) != 16 {
		return nil, fmt.Errorf("SRv6 SID must be 16 bytes, got %d", len(sid.SID))
	}
	addr := netip.AddrFrom16([16]byte(sid.SID))
	if !addr.IsValid() {
		return nil, fmt.Errorf("invalid SRv6 SID")
	}
	return json.Marshal(struct {
		SID string `json:"srv6_sid"`
	}{
		SID: addr.String(),
	})
}

// UnmarshalSRv6SID instantiates SRv6 SID object from a slice of bytes
func UnmarshalSRv6SID(b []byte) (*SRv6SID, error) {
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

// UnmarshalJSON instantiates SRv6SID object from  a slice of bytes
func (sid *SRv6SID) UnmarshalJSON(b []byte) error {
	t := struct {
		SID string `json:"srv6_sid"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(t.SID)
	if err != nil {
		return fmt.Errorf("invalid SRv6 SID: %w", err)
	}
	if addr.Is4() {
		return fmt.Errorf("SRv6 SID must be IPv6 address")
	}
	sid.SID = addr.AsSlice()

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
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes for SR Type1 Descriptor: got %d, want at least 1", len(b))
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

// UnmarshalJSON instantiates SRType1Descriptor object from a slice of bytes
func (d *SRType1Descriptor) UnmarshalJSON(b []byte) error {
	t := struct {
		Algorithm uint8 `json:"algorithm"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	d.Algorithm = t.Algorithm
	return nil
}

// SRType3Descriptor is the descriptor for SegmentType3 (SR-MPLS Prefix SID, IPv4 node address).
type SRType3Descriptor struct {
	Algorithm       uint8  `json:"algorithm"`
	IPv4NodeAddress []byte `json:"ipv4_node_address"`
}

var _ SegmentDescriptor = &SRType3Descriptor{}

// UnmarshalSRType3Descriptor instantiates an SRType3Descriptor from a 5-byte slice.
func UnmarshalSRType3Descriptor(b []byte) (SegmentDescriptor, error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("not enough bytes for SR Type3 Descriptor: got %d, want at least 5", len(b))
	}
	d := &SRType3Descriptor{
		Algorithm:       b[0],
		IPv4NodeAddress: append([]byte(nil), b[1:5]...),
	}
	return d, nil
}

// Len returns the byte length of an SRType3Descriptor.
func (d *SRType3Descriptor) Len() int { return 5 }

// MarshalJSON serializes SRType3Descriptor.
func (d *SRType3Descriptor) MarshalJSON() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("SRType3Descriptor is nil")
	}
	if len(d.IPv4NodeAddress) != 4 {
		return nil, fmt.Errorf("IPv4NodeAddress must be 4 bytes, got %d", len(d.IPv4NodeAddress))
	}
	addr := netip.AddrFrom4([4]byte(d.IPv4NodeAddress))
	if !addr.IsValid() {
		return nil, fmt.Errorf("invalid IPv4NodeAddress")
	}
	return json.Marshal(struct {
		IPv4NodeAddress string `json:"ipv4_node_address"`
		Algorithm       uint8  `json:"algorithm"`
	}{IPv4NodeAddress: addr.String(), Algorithm: d.Algorithm})
}

// UnmarshalJSON deserializes SRType3Descriptor.
func (d *SRType3Descriptor) UnmarshalJSON(b []byte) error {
	t := struct {
		IPv4NodeAddress string `json:"ipv4_node_address"`
		Algorithm       uint8  `json:"algorithm"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(t.IPv4NodeAddress)
	if err != nil {
		return fmt.Errorf("invalid IPv4NodeAddress: %w", err)
	}
	if !addr.Is4() {
		return fmt.Errorf("SR Type3 Descriptor must have an IPv4 address")
	}
	d.IPv4NodeAddress = addr.AsSlice()
	d.Algorithm = t.Algorithm
	return nil
}

// SRType4Descriptor is the descriptor for SegmentType4 (SR-MPLS Prefix SID, IPv6 node address)
// and SegmentType9 (SRv6 END SID, IPv6 node address). Both carry a 16-byte node address and
// a 1-byte SR algorithm, for a total of 17 bytes.
type SRType4Descriptor struct {
	IPv6NodeAddress []byte `json:"ipv6_node_address"`
	Algorithm       uint8  `json:"algorithm"`
}

var _ SegmentDescriptor = &SRType4Descriptor{}

// UnmarshalSRType4Descriptor instantiates an SRType4Descriptor from a 17-byte slice.
func UnmarshalSRType4Descriptor(b []byte) (SegmentDescriptor, error) {
	if len(b) < 17 {
		return nil, fmt.Errorf("not enough bytes for SR Type4 Descriptor: got %d, want at least 17", len(b))
	}
	d := &SRType4Descriptor{
		Algorithm:       b[0],
		IPv6NodeAddress: append([]byte(nil), b[1:17]...),
	}
	return d, nil
}

// Len returns the byte length of an SRType4Descriptor.
func (d *SRType4Descriptor) Len() int { return 17 }

// MarshalJSON serializes SRType4Descriptor.
func (d *SRType4Descriptor) MarshalJSON() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("SRType4Descriptor is nil")
	}
	if len(d.IPv6NodeAddress) != 16 {
		return nil, fmt.Errorf("IPv6NodeAddress must be 16 bytes, got %d", len(d.IPv6NodeAddress))
	}
	addr := netip.AddrFrom16([16]byte(d.IPv6NodeAddress))
	if !addr.IsValid() {
		return nil, fmt.Errorf("invalid IPv6NodeAddress")
	}
	return json.Marshal(struct {
		IPv6NodeAddress string `json:"ipv6_node_address"`
		Algorithm       uint8  `json:"algorithm"`
	}{IPv6NodeAddress: addr.String(), Algorithm: d.Algorithm})
}

// UnmarshalJSON deserializes SRType4Descriptor.
func (d *SRType4Descriptor) UnmarshalJSON(b []byte) error {
	t := struct {
		IPv6NodeAddress string `json:"ipv6_node_address"`
		Algorithm       uint8  `json:"algorithm"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(t.IPv6NodeAddress)
	if err != nil {
		return fmt.Errorf("invalid IPv6NodeAddress: %w", err)
	}
	if addr.Is4() {
		return fmt.Errorf("SR Type4 Descriptor must have an IPv6 address")
	}
	d.IPv6NodeAddress = addr.AsSlice()
	d.Algorithm = t.Algorithm
	return nil
}

// SRType5Descriptor is the descriptor for SegmentType5 (SR-MPLS Adjacency SID,
// IPv4 local node address and local interface ID). Carries a 4-byte IPv4 node
// address and a 4-byte interface ID, for a total of 8 bytes.
type SRType5Descriptor struct {
	LocalNodeIPv4    []byte `json:"local_node_ipv4"`
	LocalInterfaceID uint32 `json:"local_interface_id"`
}

var _ SegmentDescriptor = &SRType5Descriptor{}

// UnmarshalSRType5Descriptor instantiates an SRType5Descriptor from an 8-byte slice.
func UnmarshalSRType5Descriptor(b []byte) (SegmentDescriptor, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("not enough bytes for SR Type5 Descriptor: got %d, want at least 8", len(b))
	}
	d := &SRType5Descriptor{
		LocalNodeIPv4:    append([]byte(nil), b[:4]...),
		LocalInterfaceID: binary.BigEndian.Uint32(b[4:8]),
	}
	return d, nil
}

// Len returns the byte length of an SRType5Descriptor.
func (d *SRType5Descriptor) Len() int { return 8 }

// MarshalJSON serializes SRType5Descriptor.
func (d *SRType5Descriptor) MarshalJSON() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("SRType5Descriptor is nil")
	}
	if len(d.LocalNodeIPv4) != 4 {
		return nil, fmt.Errorf("LocalNodeIPv4 must be 4 bytes, got %d", len(d.LocalNodeIPv4))
	}
	addr := netip.AddrFrom4([4]byte(d.LocalNodeIPv4))
	if !addr.IsValid() {
		return nil, fmt.Errorf("invalid LocalNodeIPv4")
	}
	return json.Marshal(struct {
		LocalNodeIPv4    string `json:"local_node_ipv4"`
		LocalInterfaceID uint32 `json:"local_interface_id"`
	}{LocalNodeIPv4: addr.String(), LocalInterfaceID: d.LocalInterfaceID})
}

// UnmarshalJSON deserializes SRType5Descriptor.
func (d *SRType5Descriptor) UnmarshalJSON(b []byte) error {
	t := struct {
		LocalNodeIPv4    string `json:"local_node_ipv4"`
		LocalInterfaceID uint32 `json:"local_interface_id"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(t.LocalNodeIPv4)
	if err != nil {
		return fmt.Errorf("invalid LocalNodeIPv4: %w", err)
	}
	if !addr.Is4() {
		return fmt.Errorf("SR Type5 Descriptor must have an IPv4 address")
	}
	d.LocalNodeIPv4 = addr.AsSlice()
	d.LocalInterfaceID = t.LocalInterfaceID
	return nil
}

// SRType6Descriptor is the descriptor for SegmentType6 (SR-MPLS Adjacency SID,
// IPv4 local and remote interface addresses). Carries two 4-byte IPv4 addresses,
// for a total of 8 bytes.
type SRType6Descriptor struct {
	LocalInterfaceIPv4  []byte `json:"local_interface_ipv4"`
	RemoteInterfaceIPv4 []byte `json:"remote_interface_ipv4"`
}

var _ SegmentDescriptor = &SRType6Descriptor{}

// UnmarshalSRType6Descriptor instantiates an SRType6Descriptor from an 8-byte slice.
func UnmarshalSRType6Descriptor(b []byte) (SegmentDescriptor, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("not enough bytes for SR Type6 Descriptor: got %d, want at least 8", len(b))
	}
	d := &SRType6Descriptor{
		LocalInterfaceIPv4:  append([]byte(nil), b[:4]...),
		RemoteInterfaceIPv4: append([]byte(nil), b[4:8]...),
	}
	return d, nil
}

// Len returns the byte length of an SRType6Descriptor.
func (d *SRType6Descriptor) Len() int { return 8 }

// MarshalJSON serializes SRType6Descriptor.
func (d *SRType6Descriptor) MarshalJSON() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("SRType6Descriptor is nil")
	}
	if len(d.LocalInterfaceIPv4) != 4 {
		return nil, fmt.Errorf("LocalInterfaceIPv4 must be 4 bytes, got %d", len(d.LocalInterfaceIPv4))
	}
	if len(d.RemoteInterfaceIPv4) != 4 {
		return nil, fmt.Errorf("RemoteInterfaceIPv4 must be 4 bytes, got %d", len(d.RemoteInterfaceIPv4))
	}
	addrLocal := netip.AddrFrom4([4]byte(d.LocalInterfaceIPv4))
	if !addrLocal.IsValid() {
		return nil, fmt.Errorf("invalid LocalInterfaceIPv4")
	}
	addrRemote := netip.AddrFrom4([4]byte(d.RemoteInterfaceIPv4))
	if !addrRemote.IsValid() {
		return nil, fmt.Errorf("invalid RemoteInterfaceIPv4")
	}
	return json.Marshal(struct {
		LocalInterfaceIPv4  string `json:"local_interface_ipv4"`
		RemoteInterfaceIPv4 string `json:"remote_interface_ipv4"`
	}{LocalInterfaceIPv4: addrLocal.String(), RemoteInterfaceIPv4: addrRemote.String()})
}

// UnmarshalJSON deserializes SRType6Descriptor.
func (d *SRType6Descriptor) UnmarshalJSON(b []byte) error {
	t := struct {
		LocalInterfaceIPv4  string `json:"local_interface_ipv4"`
		RemoteInterfaceIPv4 string `json:"remote_interface_ipv4"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	addrLocal, err := netip.ParseAddr(t.LocalInterfaceIPv4)
	if err != nil {
		return fmt.Errorf("invalid LocalInterfaceIPv4: %w", err)
	}
	if !addrLocal.Is4() {
		return fmt.Errorf("SR Type6 Descriptor must have an IPv4 address for LocalInterfaceIPv4")
	}
	addrRemote, err := netip.ParseAddr(t.RemoteInterfaceIPv4)
	if err != nil {
		return fmt.Errorf("invalid RemoteInterfaceIPv4: %w", err)
	}
	if !addrRemote.Is4() {
		return fmt.Errorf("SR Type6 Descriptor must have an IPv4 address for RemoteInterfaceIPv4")
	}
	d.LocalInterfaceIPv4 = addrLocal.AsSlice()
	d.RemoteInterfaceIPv4 = addrRemote.AsSlice()

	return nil
}

// SRType7Descriptor is the descriptor for SegmentType7 (SR-MPLS Adjacency SID,
// IPv6 local and remote node addresses with interface IDs) and SegmentType10
// (SRv6 END.X SID, same topology encoding). Carries two 16-byte IPv6 node
// addresses and two 4-byte interface IDs, for a total of 40 bytes.
type SRType7Descriptor struct {
	LocalNodeIPv6     []byte `json:"local_node_ipv6"`
	LocalInterfaceID  uint32 `json:"local_interface_id"`
	RemoteNodeIPv6    []byte `json:"remote_node_ipv6"`
	RemoteInterfaceID uint32 `json:"remote_interface_id"`
}

var _ SegmentDescriptor = &SRType7Descriptor{}

// UnmarshalSRType7Descriptor instantiates an SRType7Descriptor from a 40-byte slice.
func UnmarshalSRType7Descriptor(b []byte) (SegmentDescriptor, error) {
	if len(b) < 40 {
		return nil, fmt.Errorf("not enough bytes for SR Type7 Descriptor: got %d, want at least 40", len(b))
	}
	d := &SRType7Descriptor{
		LocalNodeIPv6:     append([]byte(nil), b[:16]...),
		LocalInterfaceID:  binary.BigEndian.Uint32(b[16:20]),
		RemoteNodeIPv6:    append([]byte(nil), b[20:36]...),
		RemoteInterfaceID: binary.BigEndian.Uint32(b[36:40]),
	}
	return d, nil
}

// Len returns the byte length of an SRType7Descriptor.
func (d *SRType7Descriptor) Len() int { return 40 }

// MarshalJSON serializes SRType7Descriptor.
func (d *SRType7Descriptor) MarshalJSON() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("SRType7Descriptor is nil")
	}
	if len(d.LocalNodeIPv6) != 16 {
		return nil, fmt.Errorf("LocalNodeIPv6 must be 16 bytes, got %d", len(d.LocalNodeIPv6))
	}
	if len(d.RemoteNodeIPv6) != 16 {
		return nil, fmt.Errorf("RemoteNodeIPv6 must be 16 bytes, got %d", len(d.RemoteNodeIPv6))
	}
	addrLocal := netip.AddrFrom16([16]byte(d.LocalNodeIPv6))
	if !addrLocal.IsValid() {
		return nil, fmt.Errorf("invalid LocalNodeIPv6")
	}
	addrRemote := netip.AddrFrom16([16]byte(d.RemoteNodeIPv6))
	if !addrRemote.IsValid() {
		return nil, fmt.Errorf("invalid RemoteNodeIPv6")
	}
	return json.Marshal(struct {
		LocalNodeIPv6     string `json:"local_node_ipv6"`
		LocalInterfaceID  uint32 `json:"local_interface_id"`
		RemoteNodeIPv6    string `json:"remote_node_ipv6"`
		RemoteInterfaceID uint32 `json:"remote_interface_id"`
	}{
		LocalNodeIPv6:     addrLocal.String(),
		LocalInterfaceID:  d.LocalInterfaceID,
		RemoteNodeIPv6:    addrRemote.String(),
		RemoteInterfaceID: d.RemoteInterfaceID,
	})
}

// UnmarshalJSON deserializes SRType7Descriptor.
func (d *SRType7Descriptor) UnmarshalJSON(b []byte) error {
	t := struct {
		LocalNodeIPv6     string `json:"local_node_ipv6"`
		LocalInterfaceID  uint32 `json:"local_interface_id"`
		RemoteNodeIPv6    string `json:"remote_node_ipv6"`
		RemoteInterfaceID uint32 `json:"remote_interface_id"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	blna, err := netip.ParseAddr(t.LocalNodeIPv6)
	if err != nil {
		return fmt.Errorf("invalid LocalNodeIPv6: %w", err)
	}
	if !blna.Is6() {
		return fmt.Errorf("SR Type7 Descriptor must have an IPv6 address for LocalNodeIPv6")
	}
	brna, err := netip.ParseAddr(t.RemoteNodeIPv6)
	if err != nil {
		return fmt.Errorf("invalid RemoteNodeIPv6: %w", err)
	}
	d.LocalNodeIPv6 = append([]byte(nil), blna.AsSlice()...)
	if !brna.Is6() {
		return fmt.Errorf("SR Type7 Descriptor must have an IPv6 address for RemoteNodeIPv6")
	}
	d.LocalInterfaceID = t.LocalInterfaceID
	d.RemoteNodeIPv6 = append([]byte(nil), brna.AsSlice()...)
	d.RemoteInterfaceID = t.RemoteInterfaceID
	return nil
}

// SRType8Descriptor is the descriptor for SegmentType8 (SR-MPLS Adjacency SID,
// IPv6 local and remote interface addresses) and SegmentType11 (SRv6 END.X SID,
// same topology encoding). Carries two 16-byte IPv6 interface addresses, for a
// total of 32 bytes.
type SRType8Descriptor struct {
	LocalInterfaceIPv6  []byte `json:"local_interface_ipv6"`
	RemoteInterfaceIPv6 []byte `json:"remote_interface_ipv6"`
}

var _ SegmentDescriptor = &SRType8Descriptor{}

// UnmarshalSRType8Descriptor instantiates an SRType8Descriptor from a 32-byte slice.
func UnmarshalSRType8Descriptor(b []byte) (SegmentDescriptor, error) {
	if len(b) < 32 {
		return nil, fmt.Errorf("not enough bytes for SR Type8 Descriptor: got %d, want at least 32", len(b))
	}
	d := &SRType8Descriptor{
		LocalInterfaceIPv6:  append([]byte(nil), b[:16]...),
		RemoteInterfaceIPv6: append([]byte(nil), b[16:32]...),
	}
	return d, nil
}

// Len returns the byte length of an SRType8Descriptor.
func (d *SRType8Descriptor) Len() int { return 32 }

// MarshalJSON serializes SRType8Descriptor.
func (d *SRType8Descriptor) MarshalJSON() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("SRType8Descriptor is nil")
	}
	if len(d.LocalInterfaceIPv6) != 16 {
		return nil, fmt.Errorf("LocalInterfaceIPv6 must be 16 bytes, got %d", len(d.LocalInterfaceIPv6))
	}
	if len(d.RemoteInterfaceIPv6) != 16 {
		return nil, fmt.Errorf("RemoteInterfaceIPv6 must be 16 bytes, got %d", len(d.RemoteInterfaceIPv6))
	}
	addrLocal := netip.AddrFrom16([16]byte(d.LocalInterfaceIPv6))
	if !addrLocal.IsValid() {
		return nil, fmt.Errorf("invalid LocalInterfaceIPv6")
	}
	addrRemote := netip.AddrFrom16([16]byte(d.RemoteInterfaceIPv6))
	if !addrRemote.IsValid() {
		return nil, fmt.Errorf("invalid RemoteInterfaceIPv6")
	}
	return json.Marshal(struct {
		LocalInterfaceIPv6  string `json:"local_interface_ipv6"`
		RemoteInterfaceIPv6 string `json:"remote_interface_ipv6"`
	}{LocalInterfaceIPv6: addrLocal.String(), RemoteInterfaceIPv6: addrRemote.String()})
}

// UnmarshalJSON deserializes SRType8Descriptor.
func (d *SRType8Descriptor) UnmarshalJSON(b []byte) error {
	t := struct {
		LocalInterfaceIPv6  string `json:"local_interface_ipv6"`
		RemoteInterfaceIPv6 string `json:"remote_interface_ipv6"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	addrLocal, err := netip.ParseAddr(t.LocalInterfaceIPv6)
	if err != nil {
		return fmt.Errorf("invalid LocalInterfaceIPv6: %w", err)
	}
	if !addrLocal.Is6() {
		return fmt.Errorf("SR Type8 Descriptor must have an IPv6 address for LocalInterfaceIPv6")
	}
	addrRemote, err := netip.ParseAddr(t.RemoteInterfaceIPv6)
	if err != nil {
		return fmt.Errorf("invalid RemoteInterfaceIPv6: %w", err)
	}
	if !addrRemote.Is6() {
		return fmt.Errorf("SR Type8 Descriptor must have an IPv6 address for RemoteInterfaceIPv6")
	}
	bla := addrLocal.As16()
	bra := addrRemote.As16()
	d.LocalInterfaceIPv6 = bla[:]
	d.RemoteInterfaceIPv6 = bra[:]

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
		return nil, fmt.Errorf("not enough bytes to decode SR Segment Sub TLV: need at least 4 bytes, have %d", len(b))
	}
	s := make(map[uint16]SRSegmentSubTLV)
	p := 0
	for p+4 <= len(b) {
		t := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+int(l) > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode SR Segment Sub TLV")
		}
		// No Sub Sub TLVs currently defined
		switch t {
		}
		p += int(l)
	}
	if p != len(b) {
		return nil, fmt.Errorf("SR Segment Sub TLV: %d trailing bytes", len(b)-p)
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
	case SegmentTypeInvalid:
		return nil, fmt.Errorf("invalid segment type 0")
	case SegmentType1:
		s.Segment = SegmentType1
		if s.FlagS {
			if len(b) < p+8 {
				return nil, fmt.Errorf("not enough bytes for MPLS SID in segment type 1: got %d, want at least %d", len(b), p+8)
			}
			s.SID, err = UnmarshalMPLSLabelSID(b[p+4 : p+8])
			if err != nil {
				return nil, err
			}
		}
	case SegmentType2:
		s.Segment = SegmentType2
		if s.FlagS {
			if len(b) < p+20 {
				return nil, fmt.Errorf("not enough bytes for SRv6 SID in segment type 2: got %d, want at least %d", len(b), p+20)
			}
			s.SID, err = UnmarshalSRv6SID(b[p+4 : p+20])
			if err != nil {
				return nil, err
			}
		}
	case SegmentType3, SegmentType4, SegmentType5, SegmentType6, SegmentType7, SegmentType8:
		// SR-MPLS types: optional 4-byte MPLS Label SID.
		s.Segment = t
		if s.FlagS {
			if len(b) < p+8 {
				return nil, fmt.Errorf("not enough bytes for MPLS SID in segment type %d: got %d, want at least %d", t, len(b), p+8)
			}
			s.SID, err = UnmarshalMPLSLabelSID(b[p+4 : p+8])
			if err != nil {
				return nil, err
			}
		}
	case SegmentType9, SegmentType10, SegmentType11:
		// SRv6 types: optional 16-byte IPv6 SID.
		s.Segment = t
		if s.FlagS {
			if len(b) < p+20 {
				return nil, fmt.Errorf("not enough bytes for SRv6 SID in segment type %d: got %d, want at least %d", t, len(b), p+20)
			}
			s.SID, err = UnmarshalSRv6SID(b[p+4 : p+20])
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unknown segment type %d", t)
	}
	// Adjust pointer by 4 bytes (Segment Type, Reserved and 2 bytes of Flags) + length of SID.
	// SID is only present when FlagS is set; avoid nil dereference when it is absent.
	sidLen := 0
	if s.SID != nil {
		sidLen = s.SID.Len()
	}
	p += 4 + sidLen
	// RFC 9857 defines a type-specific segment descriptor as part of every
	// segment encoding. The A flag indicates whether the algorithm in that
	// descriptor is valid; it does not indicate whether the descriptor bytes
	// are present. In particular, Type 1 and Type 2 always carry the one-byte
	// Algorithm descriptor even when A is clear. Decode and consume the
	// descriptor independently of the A flag so following sub-sub-TLVs are
	// framed at the correct offset.
	if p >= len(b) {
		return nil, fmt.Errorf("segment type %d has no segment descriptor", t)
	}
	switch t {
	case SegmentType1, SegmentType2:
		// Type 2 shares the one-byte Algorithm descriptor with Type 1.
		if s.SegmentDescriptor, err = UnmarshalSRType1Descriptor(b[p:]); err != nil {
			return nil, err
		}
	case SegmentType3:
		if s.SegmentDescriptor, err = UnmarshalSRType3Descriptor(b[p:]); err != nil {
			return nil, err
		}
	case SegmentType4, SegmentType9:
		// Type 9 (SRv6 END SID) shares the descriptor layout with Type 4.
		if s.SegmentDescriptor, err = UnmarshalSRType4Descriptor(b[p:]); err != nil {
			return nil, err
		}
	case SegmentType5:
		if s.SegmentDescriptor, err = UnmarshalSRType5Descriptor(b[p:]); err != nil {
			return nil, err
		}
	case SegmentType6:
		if s.SegmentDescriptor, err = UnmarshalSRType6Descriptor(b[p:]); err != nil {
			return nil, err
		}
	case SegmentType7, SegmentType10:
		// Type 10 (SRv6 END.X SID) shares the descriptor layout with Type 7.
		if s.SegmentDescriptor, err = UnmarshalSRType7Descriptor(b[p:]); err != nil {
			return nil, err
		}
	case SegmentType8, SegmentType11:
		// Type 11 (SRv6 END.X SID) shares the descriptor layout with Type 8.
		if s.SegmentDescriptor, err = UnmarshalSRType8Descriptor(b[p:]); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("segment descriptor of type %d is not supported", t)
	}
	if s.SegmentDescriptor == nil {
		return nil, fmt.Errorf("segment descriptor of type %d is nil", t)
	}
	p += s.SegmentDescriptor.Len()
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
		Segment           SegmentType                `json:"segment_type"`
		FlagS             bool                       `json:"s_flag"`
		FlagE             bool                       `json:"e_flag"`
		FlagV             bool                       `json:"v_flag"`
		FlagR             bool                       `json:"r_flag"`
		FlagA             bool                       `json:"a_flag"`
		SID               SID                        `json:"sid"`
		SegmentDescriptor SegmentDescriptor          `json:"segment_descriptor,omitempty"`
		SubTLV            map[uint16]SRSegmentSubTLV `json:"subtlv,omitempty"`
	}{
		Segment:           s.Segment,
		FlagS:             s.FlagS,
		FlagE:             s.FlagE,
		FlagV:             s.FlagV,
		FlagR:             s.FlagR,
		FlagA:             s.FlagA,
		SID:               s.SID,
		SegmentDescriptor: s.SegmentDescriptor,
		SubTLV:            s.SubTLV,
	})
}

// UnmarshalJSON instantiates SRSegment object from  a slice of bytes
func (s *SRSegment) UnmarshalJSON(b []byte) error {
	t := struct {
		Segment SegmentType     `json:"segment_type"`
		FlagS   bool            `json:"s_flag"`
		FlagE   bool            `json:"e_flag"`
		FlagV   bool            `json:"v_flag"`
		FlagR   bool            `json:"r_flag"`
		FlagA   bool            `json:"a_flag"`
		SID     json.RawMessage `json:"sid"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	s.Segment = t.Segment
	s.FlagS = t.FlagS
	s.FlagE = t.FlagE
	s.FlagV = t.FlagV
	s.FlagR = t.FlagR
	s.FlagA = t.FlagA
	// Decode the concrete SID type based on segment_type.
	// SID is only present when the raw JSON is non-null.
	if len(t.SID) > 0 && string(t.SID) != "null" {
		switch t.Segment {
		case SegmentType2, SegmentType9, SegmentType10, SegmentType11:
			sid := &SRv6SID{}
			if err := json.Unmarshal(t.SID, sid); err != nil {
				return err
			}
			s.SID = sid
		default:
			// Types 1, 3, 4, 5, 6, 7, 8 use MPLS label SID.
			sid := &MPLSLabelSID{}
			if err := json.Unmarshal(t.SID, sid); err != nil {
				return err
			}
			s.SID = sid
		}
	}

	return nil
}

// SRMetricType defines type for SR Metric Type
type SRMetricType uint8

const (
	SRPMetricIGP                         SRMetricType = 0
	SRMetricMinUnidirectionalDelay       SRMetricType = 1
	SRMetricTE                           SRMetricType = 2
	SRMetricHopCount                     SRMetricType = 3
	SRMetricSIDListLength                SRMetricType = 4
	SRMetricBandwidth                    SRMetricType = 5
	SRMetricAverageUnidirectionalDelay   SRMetricType = 6
	SRMetricUnidirectionalDelayVariation SRMetricType = 7
	SRMetricLoss                         SRMetricType = 8
)

var _ SRSegmentListSubTLV = &SRSegmentListMetric{}

// SRSegmentListMetric defines the metric used for computation of the SID-List.
type SRSegmentListMetric struct {
	Metric SRMetricType `json:"metric_type"`
	FlagM  bool         `json:"m_flag"`
	FlagA  bool         `json:"a_flag"`
	FlagB  bool         `json:"b_flag"`
	FlagV  bool         `json:"v_flag"`
	Margin uint32       `json:"metric_margin"`
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
		Margin uint32       `json:"metric_margin"`
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
	t := struct {
		Metric SRMetricType `json:"metric_type"`
		FlagM  bool         `json:"m_flag"`
		FlagA  bool         `json:"a_flag"`
		FlagB  bool         `json:"b_flag"`
		FlagV  bool         `json:"v_flag"`
		Margin uint32       `json:"metric_margin"`
		Bound  uint32       `json:"metric_bound"`
		Value  uint32       `json:"metric_value"`
	}{}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	m.Metric = t.Metric
	m.FlagM = t.FlagM
	m.FlagA = t.FlagA
	m.FlagB = t.FlagB
	m.FlagV = t.FlagV
	m.Margin = t.Margin
	m.Bound = t.Bound
	m.Value = t.Value

	return nil
}

//   - Type 1212: SRv6 Binding SID TLV (Section 5.2).

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           BSID Flags          |            RESERVED           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Binding SID (16 octets)                   //
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                Specified Binding SID (16 octets)             //
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// //   sub-TLVs (variable)                                       //
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

//  0                   1
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |B|U|F|                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type SRv6BindingSID struct {
	FlagB bool     `json:"b_flag"`
	FlagU bool     `json:"u_flag"`
	FlagF bool     `json:"f_flag"`
	BSID  *SRv6SID `json:"binding_sid,omitempty"`
	SBSID *SRv6SID `json:"specified_binding_sid,omitempty"`
	// TLV 1250
	EndpointBehavior *srv6.EndpointBehavior `json:"endpoint_behavior,omitempty"`
	// TLV 1252
	SIDStructure   *srv6.SIDStructure `json:"sid_structure,omitempty"`
	UnknownSubTLVs []TLV              `json:"unknown_tlvs,omitempty"`
}

func UnmarshalSRv6BindingSID(b []byte) (*SRv6BindingSID, error) {
	if glog.V(6) {
		glog.Infof("SRv6 Binding SID Raw: %s", tools.MessageHex(b))
	}
	s := &SRv6BindingSID{}
	if len(b) < 36 {
		return nil, fmt.Errorf("not enough bytes for SRv6 Binding SID, need at least 36, got %d", len(b))
	}
	p := 0
	s.FlagB = b[p]&0x80 != 0
	s.FlagU = b[p]&0x40 != 0
	s.FlagF = b[p]&0x20 != 0
	p += 2
	// Ignore Reserved bytes
	p += 2
	bs, err := UnmarshalSRv6SID(b[p : p+16])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SRv6 SID: %v", err)
	}
	s.BSID = bs
	p += 16
	sbs, err := UnmarshalSRv6SID(b[p : p+16])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal specified SRv6 SID: %v", err)
	}
	s.SBSID = sbs
	p += 16
	for p < len(b) {
		if len(b)-p < 4 {
			return nil, fmt.Errorf("truncated sub-TLV header")
		}
		t := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+int(l) > len(b) {
			return nil, fmt.Errorf("sub-TLV length exceeds available bytes")
		}
		switch t {
		case 1250:
			if l != 4 {
				return nil, fmt.Errorf("invalid Endpoint Behavior sub-TLV length: %d", l)
			}
			eb, err := srv6.UnmarshalSRv6EndpointBehaviorTLV(b[p : p+int(l)])
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal Endpoint Behavior sub-TLV: %v", err)
			}
			s.EndpointBehavior = eb
		case 1252:
			if l != 4 {
				return nil, fmt.Errorf("invalid SID Structure sub-TLV length: %d", l)
			}
			ss, err := srv6.UnmarshalSRv6SIDStructureTLV(b[p : p+int(l)])
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal SID Structure sub-TLV: %v", err)
			}
			s.SIDStructure = ss
		default:
			subTLV := TLV{
				Type:   t,
				Length: l,
				Value:  b[p : p+int(l)],
			}
			s.UnknownSubTLVs = append(s.UnknownSubTLVs, subTLV)
		}
		p += int(l)
	}

	return s, nil
}

//   - Type 1213: SR Policy Name TLV (Section 5.4).

type SRPolicyName struct {
	Name string `json:"sr_policy_name,omitempty"`
}

func UnmarshalSRPolicyName(b []byte) (*SRPolicyName, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty SR Policy Name TLV")
	}
	return &SRPolicyName{
		Name: string(b),
	}, nil
}

//   - Type 1214: SR Bidirectional Group Constraint sub-TLV (Section 5.6.5).

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Type            |              Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Flags            |            RESERVED           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Bidirectional Group Identifier (variable)         //
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

//  0                   1
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |R|C|                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type SRBidirectionalGroupConstraint struct {
	FlagR                bool    `json:"r_flag"`
	FlagC                bool    `json:"c_flag"`
	BidirectionalGroupID *uint32 `json:"bidirectional_group_id,omitempty"`
	PCEPAssociationObj   []byte  `json:"pcep_association_obj,omitempty"`
}

func UnmarshalSRBidirGroupConstrant(b []byte) (*SRBidirectionalGroupConstraint, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("truncated SR Bidirectional Group Constraint sub-TLV")
	}
	p := 0
	s := &SRBidirectionalGroupConstraint{
		FlagR: b[0]&0x80 != 0,
		FlagC: b[0]&0x40 != 0,
	}
	p += 2
	// Ignore 2 reserved bytes
	p += 2
	if len(b) > 8 {
		s.PCEPAssociationObj = b[p:]
	} else {
		id := binary.BigEndian.Uint32(b[p:])
		s.BidirectionalGroupID = &id
	}
	return s, nil
}

//   - Type 1215: SR Metric Constraint sub-TLV (Section 5.6.6).

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Type             |             Length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Metric Type  |      Flags    |          RESERVED             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Metric Margin                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Metric Bound                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

//  0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |O|M|A|B|       |
// +-+-+-+-+-+-+-+-+

type SRMetricConstraint struct {
	MetricType   SRMetricType `json:"metric_type"`
	FlagO        bool         `json:"o_flag"`
	FlagM        bool         `json:"m_flag"`
	FlagA        bool         `json:"a_flag"`
	FlagB        bool         `json:"b_flag"`
	MetricMargin uint32       `json:"metric_margin"`
	MetricBound  uint32       `json:"metric_bound"`
}

func UnmarshalSRMetricConstraint(b []byte) (*SRMetricConstraint, error) {
	if len(b) != 12 {
		return nil, fmt.Errorf("invalid SR Metric Constraint sub-TLV length: %d", len(b))
	}
	p := 0
	s := &SRMetricConstraint{
		MetricType: SRMetricType(b[0]),
		FlagO:      b[1]&0x80 != 0,
		FlagM:      b[1]&0x40 != 0,
		FlagA:      b[1]&0x20 != 0,
		FlagB:      b[1]&0x10 != 0,
	}
	p += 2
	// Ignore 2 reserved bytes
	p += 2
	s.MetricMargin = binary.BigEndian.Uint32(b[p : p+4])
	s.MetricBound = binary.BigEndian.Uint32(b[p+4 : p+8])

	return s, nil
}

// - Type 1216: SR Segment List Bandwidth sub-TLV (Section 5.7.3).
type SRSegmentListBandwidth struct {
	Bandwidth float32 `json:"bandwidth"`
}

func UnmarshalSRSegmentListBandwidth(b []byte) (*SRSegmentListBandwidth, error) {
	if len(b) != 4 {
		return nil, fmt.Errorf("invalid SR Segment List Bandwidth sub-TLV length: %d", len(b))
	}
	s := &SRSegmentListBandwidth{
		Bandwidth: math.Float32frombits(binary.BigEndian.Uint32(b[:4])),
	}
	return s, nil
}

// - Type 1217: SR Segment List Identifier sub-TLV (Section 5.7.4).
type SRSegmentListIdentifier struct {
	Identifier uint32 `json:"identifier"`
}

func UnmarshalSRSegmentListIdentifier(b []byte) (*SRSegmentListIdentifier, error) {
	if len(b) != 4 {
		return nil, fmt.Errorf("invalid SR Segment List Identifier sub-TLV length: %d", len(b))
	}
	s := &SRSegmentListIdentifier{
		Identifier: binary.BigEndian.Uint32(b[:4]),
	}
	return s, nil
}

func (s *SRBidirectionalGroupConstraint) MarshalJSON() ([]byte, error) {
	type wire SRBidirectionalGroupConstraint
	return json.Marshal((*wire)(s))
}

func (s *SRBidirectionalGroupConstraint) UnmarshalJSON(b []byte) error {
	type wire SRBidirectionalGroupConstraint
	return json.Unmarshal(b, (*wire)(s))
}

func (s *SRMetricConstraint) MarshalJSON() ([]byte, error) {
	type wire SRMetricConstraint
	return json.Marshal((*wire)(s))
}

func (s *SRMetricConstraint) UnmarshalJSON(b []byte) error {
	type wire SRMetricConstraint
	return json.Unmarshal(b, (*wire)(s))
}

func (s *SRSegmentListBandwidth) MarshalJSON() ([]byte, error) {
	type wire SRSegmentListBandwidth
	return json.Marshal((*wire)(s))
}

func (s *SRSegmentListBandwidth) UnmarshalJSON(b []byte) error {
	type wire SRSegmentListBandwidth
	return json.Unmarshal(b, (*wire)(s))
}

func (s *SRSegmentListIdentifier) MarshalJSON() ([]byte, error) {
	type wire SRSegmentListIdentifier
	return json.Marshal((*wire)(s))
}

func (s *SRSegmentListIdentifier) UnmarshalJSON(b []byte) error {
	type wire SRSegmentListIdentifier
	return json.Unmarshal(b, (*wire)(s))
}

// SRPolicyState aggregates the SR Policy State TLVs carried in the BGP-LS
// path attribute for one SR Policy Candidate Path NLRI.
type SRPolicyState struct {
	BindingSID         *SRBindingSID               `json:"binding_sid,omitempty"`
	SRv6BindingSID     *SRv6BindingSID             `json:"srv6_binding_sid,omitempty"`
	CandidatePathState *SRCandidatePathState       `json:"candidate_path_state,omitempty"`
	CandidatePathName  *SRCandidatePathName        `json:"candidate_path_name,omitempty"`
	PolicyName         *SRPolicyName               `json:"policy_name,omitempty"`
	Constraints        *SRCandidatePathConstraints `json:"constraints,omitempty"`
	SegmentLists       []*SRSegmentList            `json:"segment_lists,omitempty"`
	UnknownTLV         []TLV                       `json:"unknown_tlv,omitempty"`
}

func (s *SRPolicyState) HasData() bool {
	return s != nil && (s.BindingSID != nil || s.SRv6BindingSID != nil ||
		s.CandidatePathState != nil || s.CandidatePathName != nil ||
		s.PolicyName != nil || s.Constraints != nil || len(s.SegmentLists) != 0)
}
