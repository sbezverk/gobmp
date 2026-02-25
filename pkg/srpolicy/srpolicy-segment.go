package srpolicy

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// SegmentType defines a type of Segment in Segment List
type SegmentType int

const (
	// TypeA Segment Sub-TLV encodes a single SR-MPLS SID
	TypeA SegmentType = 1
	// TypeB Segment Sub-TLV encodes a single SRv6 SID
	TypeB SegmentType = 13
	// TypeC Segment Sub-TLV encodes an IPv4 node address, SR Algorithm
	// and an optional SR-MPLS SID
	TypeC SegmentType = 3
	// TypeD Segment Sub-TLV encodes an IPv6 node address, SR Algorithm
	// and an optional SR-MPLS SID.
	TypeD SegmentType = 4
	// TypeE Segment Sub-TLV encodes an IPv4 node address, a local
	// interface Identifier (Local Interface ID) and an optional SR-MPLS
	// SID.
	TypeE SegmentType = 5
	// TypeF Segment Sub-TLV encodes an adjacency local address, an
	// adjacency remote address and an optional SR-MPLS SID.
	TypeF SegmentType = 6
	// TypeG Segment Sub-TLV encodes an IPv6 Link Local adjacency with
	// IPv6 local node address, a local interface identifier (Local
	// Interface ID), IPv6 remote node address , a remote interface
	// identifier (Remote Interface ID) and an optional SR-MPLS SID.
	TypeG SegmentType = 7
	// TypeH Segment Sub-TLV encodes an adjacency local address, an
	// adjacency remote address and an optional SR-MPLS SID.
	TypeH SegmentType = 8
	// TypeI Segment Sub-TLV encodes an IPv6 node address, SR Algorithm
	// and an optional SRv6 SID.
	TypeI SegmentType = 14
	// TypeJ Segment Sub-TLV encodes an IPv6 Link Local adjacency with
	// local node address, a local interface identifier (Local Interface
	// ID), remote IPv6 node address, a remote interface identifier (Remote
	// Interface ID) and an optional SRv6 SID.
	TypeJ SegmentType = 15
	// TypeK Segment Sub-TLV encodes an adjacency local address, an
	// adjacency remote address and an optional SRv6 SID.
	TypeK SegmentType = 16
)

// Segment sub-TLV describes a single segment in a segment list (i.e.,
// a single element of the explicit path).  One or more Segment sub-TLVs
// constitute an explicit path of the SR Policy candidate path.
type Segment interface {
	GetType() SegmentType
	GetFlags() *SegmentFlags
	MarshalJSON() ([]byte, error)
}

// SegmentList sub-TLV encodes a single explicit path towards the
// endpoint.
type SegmentList struct {
	Weight  *Weight   `json:"weight_subtlv,omitempty"`
	Segment []Segment `json:"segments,omitempty"`
}

// UnmarshalJSON is custom Unmarshal fuction which will populate Slice of Segment interfaces with correct,
// depending on the segment type value
func (sl *SegmentList) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	if b, ok := objmap["weight_subtlv"]; ok {
		if err := json.Unmarshal(b, &sl.Weight); err != nil {
			return err
		}
	}
	segs := make([]Segment, 0)
	if b, ok := objmap["segments"]; ok {
		var sgss []map[string]json.RawMessage
		if err := json.Unmarshal(b, &sgss); err != nil {
			return err
		}
		for _, s := range sgss {
			var segType SegmentType
			if err := json.Unmarshal(s["segment_type"], &segType); err != nil {
				return err
			}
			var seg Segment
			switch segType {
			case TypeA:
				t := &typeASegment{}
				if err := t.unmarshalJSONObj(s); err != nil {
					return err
				}
				seg = t
			case TypeB:
				t := &typeBSegment{}
				if err := t.unmarshalJSONObj(s); err != nil {
					return err
				}
				seg = t
			case TypeC:
				t := &typeCSegment{}
				if err := t.unmarshalJSONObj(s); err != nil {
					return err
				}
				seg = t
			case TypeD:
				t := &typeDSegment{}
				if err := t.unmarshalJSONObj(s); err != nil {
					return err
				}
				seg = t
			case TypeE:
				t := &typeESegment{}
				if err := t.unmarshalJSONObj(s); err != nil {
					return err
				}
				seg = t
			case TypeF:
				t := &typeFSegment{}
				if err := t.unmarshalJSONObj(s); err != nil {
					return err
				}
				seg = t
			case TypeG:
				t := &typeGSegment{}
				if err := t.unmarshalJSONObj(s); err != nil {
					return err
				}
				seg = t
			case TypeH:
				t := &typeHSegment{}
				if err := t.unmarshalJSONObj(s); err != nil {
					return err
				}
				seg = t
			case TypeI:
				t := &typeISegment{}
				if err := t.unmarshalJSONObj(s); err != nil {
					return err
				}
				seg = t
			case TypeJ:
				t := &typeJSegment{}
				if err := t.unmarshalJSONObj(s); err != nil {
					return err
				}
				seg = t
			case TypeK:
				return fmt.Errorf("unsupported type of segment sub tlv %d", segType)
			default:
				return fmt.Errorf("unknown type of segment sub tlv %d", segType)

			}
			segs = append(segs, seg)
		}
	}
	sl.Segment = segs

	return nil
}

// UnmarshalSegmentListSTLV instantiates an instance of SegmentList Sub TLV
func UnmarshalSegmentListSTLV(b []byte) (*SegmentList, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Segment List STLV Raw: %s", tools.MessageHex(b))
	}
	p := 0
	sl := &SegmentList{
		Segment: make([]Segment, 0),
	}
	for p < len(b) {
		t := int(b[p])
		p++
		switch t {
		case WEIGHTSTLV:
			if sl.Weight != nil {
				return nil, fmt.Errorf("Segment List Sub TLV can carry a single instance of Weight")
			}
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Weight STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 6 {
				return nil, fmt.Errorf("invalid length %d of raw data for Weight Sub TLV", l)
			}
			w := &Weight{
				Flags:  b[p],
				Weight: binary.BigEndian.Uint32(b[p+2 : p+2+4]),
			}
			sl.Weight = w
			p += int(l)
		case int(TypeA):
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Type A Segment STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 6 {
				return nil, fmt.Errorf("invalid length of Type A Segment STLV")
			}
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("insufficient data for Type A Segment Sub TLV: need %d bytes, have %d", l, len(b)-p)
			}
			s, err := UnmarshalTypeASegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeB):
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Type B Segment STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 18 {
				return nil, fmt.Errorf("invalid length of Type B Segment STLV")
			}
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("insufficient data for Type B Segment Sub TLV: need %d bytes, have %d", l, len(b)-p)
			}
			s, err := UnmarshalTypeBSegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeC):
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Type C Segment STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 6 && l != 10 {
				return nil, fmt.Errorf("invalid length of Type C Segment STLV: got %d, expected 6 or 10", l)
			}
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("insufficient data for Type C Segment Sub TLV: need %d bytes, have %d", l, len(b)-p)
			}
			s, err := UnmarshalTypeCSegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeD):
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Type D Segment STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 18 && l != 22 {
				return nil, fmt.Errorf("invalid length of Type D Segment STLV: got %d, expected 18 or 22", l)
			}
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("insufficient data for Type D Segment Sub TLV: need %d bytes, have %d", l, len(b)-p)
			}
			s, err := UnmarshalTypeDSegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeE):
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Type E Segment STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 10 && l != 14 {
				return nil, fmt.Errorf("invalid length of Type E Segment STLV: got %d, expected 10 or 14", l)
			}
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("insufficient data for Type E Segment Sub TLV: need %d bytes, have %d", l, len(b)-p)
			}
			s, err := UnmarshalTypeESegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeF):
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Type F Segment STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 10 && l != 14 {
				return nil, fmt.Errorf("invalid length of Type F Segment STLV: got %d, expected 10 or 14", l)
			}
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("insufficient data for Type F Segment Sub TLV: need %d bytes, have %d", l, len(b)-p)
			}
			s, err := UnmarshalTypeFSegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeG):
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Type G Segment STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 42 && l != 46 {
				return nil, fmt.Errorf("invalid length of Type G Segment STLV: got %d, expected 42 or 46", l)
			}
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("insufficient data for Type G Segment Sub TLV: need %d bytes, have %d", l, len(b)-p)
			}
			s, err := UnmarshalTypeGSegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeH):
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Type H Segment STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 34 && l != 38 {
				return nil, fmt.Errorf("invalid length of Type H Segment STLV: got %d, expected 34 or 38", l)
			}
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("insufficient data for Type H Segment Sub TLV: need %d bytes, have %d", l, len(b)-p)
			}
			s, err := UnmarshalTypeHSegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeI):
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Type I Segment STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 22 && l != 38 {
				return nil, fmt.Errorf("invalid length of Type I Segment STLV: got %d, expected 22 or 38", l)
			}
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("insufficient data for Type I Segment Sub TLV: need %d bytes, have %d", l, len(b)-p)
			}
			s, err := UnmarshalTypeISegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeJ):
			if p >= len(b) {
				return nil, fmt.Errorf("truncated Type J Segment STLV: missing length byte")
			}
			l := b[p]
			p++
			if l != 42 && l != 58 {
				return nil, fmt.Errorf("invalid length of Type J Segment STLV: got %d, expected 42 or 58", l)
			}
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("insufficient data for Type J Segment Sub TLV: need %d bytes, have %d", l, len(b)-p)
			}
			s, err := UnmarshalTypeJSegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeK):
			glog.Infof("Segment of type K not implemented")
		default:
			return nil, fmt.Errorf("unknown type of segment sub tlv %d", t)
		}
	}
	return sl, nil
}

// SegmentFlags defines flags a Segment of Segment list can carry
type SegmentFlags struct {
	Vflag bool `json:"v_flag"`
	Aflag bool `json:"a_flag"`
	Sflag bool `json:"s_flag"`
	Bflag bool `json:"b_flag"`
}

// UnmarshalJSON reconstructs Segment Flags object from a slice of bytes.
func (s *SegmentFlags) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	if b, ok := objmap["v_flag"]; ok {
		if err := json.Unmarshal(b, &s.Vflag); err != nil {
			return err
		}
	}
	if b, ok := objmap["a_flag"]; ok {
		if err := json.Unmarshal(b, &s.Aflag); err != nil {
			return err
		}
	}
	if b, ok := objmap["s_flag"]; ok {
		if err := json.Unmarshal(b, &s.Sflag); err != nil {
			return err
		}
	}
	if b, ok := objmap["b_flag"]; ok {
		if err := json.Unmarshal(b, &s.Bflag); err != nil {
			return err
		}
	}

	return nil
}

// NewSegmentFlags creates a new instance of SegmentFlags object
func NewSegmentFlags(b byte) *SegmentFlags {
	f := &SegmentFlags{
		Vflag: b&0x80 == 0x80,
		Aflag: b&0x40 == 0x40,
		Sflag: b&0x20 == 0x20,
		Bflag: b&0x10 == 0x10,
	}

	return f
}

// TypeASegment defines method to access Type A specifc elements
type TypeASegment interface {
	GetLabel() uint32
	GetTC() byte
	GetS() bool
	GetTTL() byte
}
type typeASegment struct {
	flags *SegmentFlags
	label uint32
	tc    byte
	s     bool
	ttl   byte
}

var _ Segment = &typeASegment{}
var _ TypeASegment = &typeASegment{}

func (ta *typeASegment) GetFlags() *SegmentFlags {
	return ta.flags
}
func (ta *typeASegment) GetType() SegmentType {
	return TypeA
}

func (ta *typeASegment) GetLabel() uint32 {
	return ta.label
}
func (ta *typeASegment) GetTC() byte {
	return ta.tc
}
func (ta *typeASegment) GetS() bool {
	return ta.s
}
func (ta *typeASegment) GetTTL() byte {
	return ta.ttl
}

func (ta *typeASegment) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SegmentType SegmentType   `json:"segment_type,omitempty"`
		Flags       *SegmentFlags `json:"flags,omitempty"`
		Label       uint32        `json:"label,omitempty"`
		TC          byte          `json:"tc,omitempty"`
		S           bool          `json:"s,omitempty"`
		TTL         byte          `json:"ttl,omitempty"`
	}{
		SegmentType: TypeA,
		Flags:       ta.flags,
		Label:       ta.label,
		TC:          ta.tc,
		S:           ta.s,
		TTL:         ta.ttl,
	})
}

func (ta *typeASegment) unmarshalJSONObj(objmap map[string]json.RawMessage) error {
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &ta.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["label"]; ok {
		if err := json.Unmarshal(b, &ta.label); err != nil {
			return err
		}
	}
	if b, ok := objmap["tc"]; ok {
		if err := json.Unmarshal(b, &ta.tc); err != nil {
			return err
		}
	}
	if b, ok := objmap["s"]; ok {
		if err := json.Unmarshal(b, &ta.s); err != nil {
			return err
		}
	}
	if b, ok := objmap["ttl"]; ok {
		if err := json.Unmarshal(b, &ta.ttl); err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalTypeASegment instantiates an instance of Type A Segment sub tlv
func UnmarshalTypeASegment(b []byte) (Segment, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Type A Segment STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 6 {
		return nil, fmt.Errorf("invalid length of Type A Segment STLV")
	}
	s := &typeASegment{}
	p := 0
	s.flags = NewSegmentFlags(b[p])
	p++
	// Skip reserved byte
	p++
	l := binary.BigEndian.Uint32(b[p : p+4])
	s.label = l >> 12
	s.tc = (b[p+2] & 0x0e) >> 1
	s.s = b[p+2]&0x01 == 0x01
	s.ttl = b[p+3]

	return s, nil
}

// TypeBSegment defines method to access Type B specific elements (SRv6 SID)
type TypeBSegment interface {
	GetSRv6SID() []byte
}

type typeBSegment struct {
	flags *SegmentFlags
	sid   []byte // 16 bytes - SRv6 SID
}

var _ Segment = &typeBSegment{}
var _ TypeBSegment = &typeBSegment{}

func (tb *typeBSegment) GetFlags() *SegmentFlags {
	return tb.flags
}

func (tb *typeBSegment) GetType() SegmentType {
	return TypeB
}

// GetSRv6SID returns a copy of the 16-byte SRv6 SID.
// Callers can safely modify the returned slice without affecting internal state.
func (tb *typeBSegment) GetSRv6SID() []byte {
	return append([]byte(nil), tb.sid...)
}

func (tb *typeBSegment) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SegmentType SegmentType   `json:"segment_type,omitempty"`
		Flags       *SegmentFlags `json:"flags,omitempty"`
		SRv6SID     []byte        `json:"srv6_sid,omitempty"`
	}{
		SegmentType: TypeB,
		Flags:       tb.flags,
		SRv6SID:     tb.sid,
	})
}

func (tb *typeBSegment) unmarshalJSONObj(objmap map[string]json.RawMessage) error {
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &tb.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["srv6_sid"]; ok {
		if err := json.Unmarshal(b, &tb.sid); err != nil {
			return err
		}
		// SRv6 SID must be exactly 16 bytes, to match UnmarshalTypeBSegment behavior.
		if len(tb.sid) != 16 {
			return fmt.Errorf("invalid SRv6 SID length: got %d bytes, want 16", len(tb.sid))
		}
	}
	return nil
}

func (tb *typeBSegment) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	return tb.unmarshalJSONObj(objmap)
}

// UnmarshalTypeBSegment instantiates an instance of Type B Segment sub tlv (SRv6 SID)
func UnmarshalTypeBSegment(b []byte) (Segment, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Type B Segment STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 18 {
		return nil, fmt.Errorf("invalid length of Type B Segment STLV")
	}
	s := &typeBSegment{}
	p := 0
	s.flags = NewSegmentFlags(b[p])
	p++
	// Skip reserved byte
	p++
	// SRv6 SID is 16 bytes (128 bits)
	s.sid = make([]byte, 16)
	copy(s.sid, b[p:p+16])

	return s, nil
}

// TypeCSegment defines methods to access Type C specific elements (IPv4 + SR Algorithm + optional SID)
type TypeCSegment interface {
	GetIPv4Address() []byte
	GetSRAlgorithm() byte
	GetSID() (uint32, bool) // SID and whether it's present
}

type typeCSegment struct {
	flags       *SegmentFlags
	srAlgorithm byte
	ipv4Address []byte  // 4 bytes
	sid         *uint32 // Optional SR-MPLS SID
}

var _ Segment = &typeCSegment{}
var _ TypeCSegment = &typeCSegment{}

func (tc *typeCSegment) GetFlags() *SegmentFlags {
	return tc.flags
}

func (tc *typeCSegment) GetType() SegmentType {
	return TypeC
}

// GetIPv4Address returns a copy of the 4-byte IPv4 address.
// Callers can safely modify the returned slice without affecting internal state.
func (tc *typeCSegment) GetIPv4Address() []byte {
	return append([]byte(nil), tc.ipv4Address...)
}

func (tc *typeCSegment) GetSRAlgorithm() byte {
	return tc.srAlgorithm
}

func (tc *typeCSegment) GetSID() (uint32, bool) {
	if tc.sid == nil {
		return 0, false
	}
	return *tc.sid, true
}

func (tc *typeCSegment) MarshalJSON() ([]byte, error) {
	type jsonSegment struct {
		SegmentType SegmentType   `json:"segment_type,omitempty"`
		Flags       *SegmentFlags `json:"flags,omitempty"`
		SRAlgorithm byte          `json:"sr_algorithm,omitempty"`
		IPv4Address []byte        `json:"ipv4_address,omitempty"`
		SID         *uint32       `json:"sid,omitempty"`
	}
	return json.Marshal(jsonSegment{
		SegmentType: TypeC,
		Flags:       tc.flags,
		SRAlgorithm: tc.srAlgorithm,
		IPv4Address: tc.ipv4Address,
		SID:         tc.sid,
	})
}

func (tc *typeCSegment) unmarshalJSONObj(objmap map[string]json.RawMessage) error {
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &tc.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["sr_algorithm"]; ok {
		if err := json.Unmarshal(b, &tc.srAlgorithm); err != nil {
			return err
		}
	}
	if b, ok := objmap["ipv4_address"]; ok {
		if err := json.Unmarshal(b, &tc.ipv4Address); err != nil {
			return err
		}
		// IPv4 address must be exactly 4 bytes, to match UnmarshalTypeCSegment behavior.
		if len(tc.ipv4Address) != 4 {
			return fmt.Errorf("invalid IPv4 address length: got %d bytes, want 4", len(tc.ipv4Address))
		}
	}
	if b, ok := objmap["sid"]; ok {
		var sid uint32
		if err := json.Unmarshal(b, &sid); err != nil {
			return err
		}
		tc.sid = &sid
	}
	return nil
}

func (tc *typeCSegment) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	return tc.unmarshalJSONObj(objmap)
}

// UnmarshalTypeCSegment instantiates an instance of Type C Segment sub tlv (IPv4 + SR Algorithm + optional SID)
func UnmarshalTypeCSegment(b []byte) (Segment, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Type C Segment STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 6 && len(b) != 10 {
		return nil, fmt.Errorf("invalid length of Type C Segment STLV: got %d, expected 6 or 10", len(b))
	}
	s := &typeCSegment{}
	p := 0
	s.flags = NewSegmentFlags(b[p])
	p++
	s.srAlgorithm = b[p]
	p++
	// IPv4 address is 4 bytes
	s.ipv4Address = make([]byte, 4)
	copy(s.ipv4Address, b[p:p+4])
	p += 4
	// Optional SID (4 bytes) if length is 10
	if len(b) == 10 {
		sid := binary.BigEndian.Uint32(b[p : p+4])
		s.sid = &sid
	}

	return s, nil
}

// TypeDSegment defines methods to access Type D specific elements (IPv6 + SR Algorithm + optional SID)
type TypeDSegment interface {
	GetIPv6Address() []byte
	GetSRAlgorithm() byte
	GetSID() (uint32, bool) // SID and whether it's present
}

type typeDSegment struct {
	flags       *SegmentFlags
	srAlgorithm byte
	ipv6Address []byte // 16 bytes
	sid         *uint32 // Optional SR-MPLS SID
}

var _ Segment = &typeDSegment{}
var _ TypeDSegment = &typeDSegment{}

func (td *typeDSegment) GetFlags() *SegmentFlags {
	return td.flags
}

func (td *typeDSegment) GetType() SegmentType {
	return TypeD
}

// GetIPv6Address returns a 16-byte copy of the IPv6 address safe for modification
func (td *typeDSegment) GetIPv6Address() []byte {
	return append([]byte(nil), td.ipv6Address...)
}

func (td *typeDSegment) GetSRAlgorithm() byte {
	return td.srAlgorithm
}

func (td *typeDSegment) GetSID() (uint32, bool) {
	if td.sid == nil {
		return 0, false
	}
	return *td.sid, true
}

func (td *typeDSegment) MarshalJSON() ([]byte, error) {
	type jsonSegment struct {
		SegmentType SegmentType   `json:"segment_type,omitempty"`
		Flags       *SegmentFlags `json:"flags,omitempty"`
		SRAlgorithm byte          `json:"sr_algorithm,omitempty"`
		IPv6Address []byte        `json:"ipv6_address,omitempty"`
		SID         *uint32       `json:"sid,omitempty"`
	}
	return json.Marshal(jsonSegment{
		SegmentType: TypeD,
		Flags:       td.flags,
		SRAlgorithm: td.srAlgorithm,
		IPv6Address: td.ipv6Address,
		SID:         td.sid,
	})
}

func (td *typeDSegment) unmarshalJSONObj(objmap map[string]json.RawMessage) error {
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &td.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["sr_algorithm"]; ok {
		if err := json.Unmarshal(b, &td.srAlgorithm); err != nil {
			return err
		}
	}
	if b, ok := objmap["ipv6_address"]; ok {
		if err := json.Unmarshal(b, &td.ipv6Address); err != nil {
			return err
		}
		// IPv6 address must be exactly 16 bytes, to match UnmarshalTypeDSegment behavior.
		if len(td.ipv6Address) != 16 {
			return fmt.Errorf("invalid IPv6 address length: got %d bytes, want 16", len(td.ipv6Address))
		}
	}
	if b, ok := objmap["sid"]; ok {
		var sid uint32
		if err := json.Unmarshal(b, &sid); err != nil {
			return err
		}
		td.sid = &sid
	}
	return nil
}

func (td *typeDSegment) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	return td.unmarshalJSONObj(objmap)
}

// UnmarshalTypeDSegment instantiates an instance of Type D Segment sub tlv (IPv6 + SR Algorithm + optional SID)
func UnmarshalTypeDSegment(b []byte) (Segment, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Type D Segment STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 18 && len(b) != 22 {
		return nil, fmt.Errorf("invalid length of Type D Segment STLV: got %d, expected 18 or 22", len(b))
	}
	s := &typeDSegment{}
	p := 0
	s.flags = NewSegmentFlags(b[p])
	p++
	s.srAlgorithm = b[p]
	p++
	// IPv6 address is 16 bytes (no reserved bytes per RFC 9831, same as Type C)
	s.ipv6Address = make([]byte, 16)
	copy(s.ipv6Address, b[p:p+16])
	p += 16
	// Optional SID (4 bytes) if length is 22
	if len(b) == 22 {
		sid := binary.BigEndian.Uint32(b[p : p+4])
		s.sid = &sid
	}

	return s, nil
}

// TypeESegment defines methods to access Type E specific elements (IPv4 + Interface ID + optional SID)
type TypeESegment interface {
	GetIPv4Address() []byte
	GetLocalInterfaceID() uint32
	GetSID() (uint32, bool) // SID and whether it's present
}

type typeESegment struct {
	flags             *SegmentFlags
	localInterfaceID  uint32
	ipv4Address       []byte  // 4 bytes
	sid               *uint32 // Optional SR-MPLS SID
}

var _ Segment = &typeESegment{}
var _ TypeESegment = &typeESegment{}

func (te *typeESegment) GetFlags() *SegmentFlags {
	return te.flags
}

func (te *typeESegment) GetType() SegmentType {
	return TypeE
}

// GetIPv4Address returns a 4-byte copy of the IPv4 address safe for modification
func (te *typeESegment) GetIPv4Address() []byte {
	return append([]byte(nil), te.ipv4Address...)
}

// GetLocalInterfaceID returns the 32-bit local interface identifier
func (te *typeESegment) GetLocalInterfaceID() uint32 {
	return te.localInterfaceID
}

// GetSID returns the optional SR-MPLS SID and whether it is present
func (te *typeESegment) GetSID() (uint32, bool) {
	if te.sid != nil {
		return *te.sid, true
	}
	return 0, false
}

func (te *typeESegment) MarshalJSON() ([]byte, error) {
	v := struct {
		SegmentType      SegmentType   `json:"segment_type,omitempty"`
		Flags            *SegmentFlags `json:"flags,omitempty"`
		LocalInterfaceID uint32        `json:"local_interface_id,omitempty"`
		IPv4Address      []byte        `json:"ipv4_address,omitempty"`
		SID              *uint32       `json:"sid,omitempty"`
	}{
		SegmentType:      TypeE,
		Flags:            te.flags,
		LocalInterfaceID: te.localInterfaceID,
		IPv4Address:      te.ipv4Address,
		SID:              te.sid,
	}
	return json.Marshal(v)
}

func (te *typeESegment) unmarshalJSONObj(objmap map[string]json.RawMessage) error {
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &te.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["local_interface_id"]; ok {
		if err := json.Unmarshal(b, &te.localInterfaceID); err != nil {
			return err
		}
	}
	if b, ok := objmap["ipv4_address"]; ok {
		if err := json.Unmarshal(b, &te.ipv4Address); err != nil {
			return err
		}
		if len(te.ipv4Address) != 4 {
			return fmt.Errorf("invalid IPv4 address length: got %d bytes, want 4", len(te.ipv4Address))
		}
	}
	if b, ok := objmap["sid"]; ok {
		var sid uint32
		if err := json.Unmarshal(b, &sid); err != nil {
			return err
		}
		te.sid = &sid
	}
	return nil
}

func (te *typeESegment) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	return te.unmarshalJSONObj(objmap)
}

// UnmarshalTypeESegment instantiates an instance of Type E Segment sub tlv (IPv4 + Interface ID + optional SID)
func UnmarshalTypeESegment(b []byte) (Segment, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Type E Segment STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 10 && len(b) != 14 {
		return nil, fmt.Errorf("invalid length of Type E Segment STLV: got %d, expected 10 or 14", len(b))
	}
	s := &typeESegment{}
	p := 0
	s.flags = NewSegmentFlags(b[p])
	p++
	// Skip reserved byte per RFC 9831
	p++
	// Local Interface ID is 4 bytes
	s.localInterfaceID = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	// IPv4 address is 4 bytes
	s.ipv4Address = make([]byte, 4)
	copy(s.ipv4Address, b[p:p+4])
	p += 4
	// Optional SID (4 bytes) if length is 14
	if len(b) == 14 {
		sid := binary.BigEndian.Uint32(b[p : p+4])
		s.sid = &sid
	}

	return s, nil
}

// TypeFSegment defines methods to access Type F specific elements (IPv4 Local/Remote adjacency + optional SID)
type TypeFSegment interface {
	GetLocalIPv4Address() []byte
	GetRemoteIPv4Address() []byte
	GetSID() (uint32, bool) // SID and whether it's present
}

type typeFSegment struct {
	flags             *SegmentFlags
	localIPv4Address  []byte  // 4 bytes
	remoteIPv4Address []byte  // 4 bytes
	sid               *uint32 // Optional SR-MPLS SID
}

var _ Segment = &typeFSegment{}
var _ TypeFSegment = &typeFSegment{}

func (tf *typeFSegment) GetFlags() *SegmentFlags {
	return tf.flags
}

func (tf *typeFSegment) GetType() SegmentType {
	return TypeF
}

// GetLocalIPv4Address returns a 4-byte copy of the local IPv4 address safe for modification
func (tf *typeFSegment) GetLocalIPv4Address() []byte {
	return append([]byte(nil), tf.localIPv4Address...)
}

// GetRemoteIPv4Address returns a 4-byte copy of the remote IPv4 address safe for modification
func (tf *typeFSegment) GetRemoteIPv4Address() []byte {
	return append([]byte(nil), tf.remoteIPv4Address...)
}

// GetSID returns the optional SR-MPLS SID and whether it is present
func (tf *typeFSegment) GetSID() (uint32, bool) {
	if tf.sid != nil {
		return *tf.sid, true
	}
	return 0, false
}

func (tf *typeFSegment) MarshalJSON() ([]byte, error) {
	v := struct {
		SegmentType       SegmentType   `json:"segment_type,omitempty"`
		Flags             *SegmentFlags `json:"flags,omitempty"`
		LocalIPv4Address  []byte        `json:"local_ipv4_address,omitempty"`
		RemoteIPv4Address []byte        `json:"remote_ipv4_address,omitempty"`
		SID               *uint32       `json:"sid,omitempty"`
	}{
		SegmentType:       TypeF,
		Flags:             tf.flags,
		LocalIPv4Address:  tf.localIPv4Address,
		RemoteIPv4Address: tf.remoteIPv4Address,
		SID:               tf.sid,
	}
	return json.Marshal(v)
}

func (tf *typeFSegment) unmarshalJSONObj(objmap map[string]json.RawMessage) error {
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &tf.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["local_ipv4_address"]; ok {
		if err := json.Unmarshal(b, &tf.localIPv4Address); err != nil {
			return err
		}
		if len(tf.localIPv4Address) != 4 {
			return fmt.Errorf("invalid local IPv4 address length: got %d bytes, want 4", len(tf.localIPv4Address))
		}
	}
	if b, ok := objmap["remote_ipv4_address"]; ok {
		if err := json.Unmarshal(b, &tf.remoteIPv4Address); err != nil {
			return err
		}
		if len(tf.remoteIPv4Address) != 4 {
			return fmt.Errorf("invalid remote IPv4 address length: got %d bytes, want 4", len(tf.remoteIPv4Address))
		}
	}
	if b, ok := objmap["sid"]; ok {
		var sid uint32
		if err := json.Unmarshal(b, &sid); err != nil {
			return err
		}
		tf.sid = &sid
	}
	return nil
}

func (tf *typeFSegment) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	return tf.unmarshalJSONObj(objmap)
}

// UnmarshalTypeFSegment instantiates an instance of Type F Segment sub tlv (IPv4 Local/Remote adjacency + optional SID)
func UnmarshalTypeFSegment(b []byte) (Segment, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Type F Segment STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 10 && len(b) != 14 {
		return nil, fmt.Errorf("invalid length of Type F Segment STLV: got %d, expected 10 or 14", len(b))
	}
	s := &typeFSegment{}
	p := 0
	s.flags = NewSegmentFlags(b[p])
	p++
	// Skip reserved byte per RFC 9831
	p++
	// Local IPv4 address is 4 bytes
	s.localIPv4Address = make([]byte, 4)
	copy(s.localIPv4Address, b[p:p+4])
	p += 4
	// Remote IPv4 address is 4 bytes
	s.remoteIPv4Address = make([]byte, 4)
	copy(s.remoteIPv4Address, b[p:p+4])
	p += 4
	// Optional SID (4 bytes) if length is 14
	if len(b) == 14 {
		sid := binary.BigEndian.Uint32(b[p : p+4])
		s.sid = &sid
	}

	return s, nil
}
// TypeGSegment defines methods to access Type G specific elements (IPv6 link-local adjacency with interface IDs + optional SID)
type TypeGSegment interface {
	GetLocalInterfaceID() uint32
	GetLocalIPv6Address() []byte
	GetRemoteInterfaceID() uint32
	GetRemoteIPv6Address() []byte
	GetSID() (uint32, bool) // SID and whether it's present
}

type typeGSegment struct {
	flags             *SegmentFlags
	localInterfaceID  uint32  // 4 bytes
	localIPv6Address  []byte  // 16 bytes
	remoteInterfaceID uint32  // 4 bytes
	remoteIPv6Address []byte  // 16 bytes
	sid               *uint32 // Optional SR-MPLS SID
}

var _ Segment = &typeGSegment{}
var _ TypeGSegment = &typeGSegment{}

func (tg *typeGSegment) GetFlags() *SegmentFlags {
	return tg.flags
}

func (tg *typeGSegment) GetType() SegmentType {
	return TypeG
}

// GetLocalInterfaceID returns the 32-bit local interface identifier
func (tg *typeGSegment) GetLocalInterfaceID() uint32 {
	return tg.localInterfaceID
}

// GetLocalIPv6Address returns a 16-byte copy of the local IPv6 address safe for modification
func (tg *typeGSegment) GetLocalIPv6Address() []byte {
	return append([]byte(nil), tg.localIPv6Address...)
}

// GetRemoteInterfaceID returns the 32-bit remote interface identifier
func (tg *typeGSegment) GetRemoteInterfaceID() uint32 {
	return tg.remoteInterfaceID
}

// GetRemoteIPv6Address returns a 16-byte copy of the remote IPv6 address safe for modification
func (tg *typeGSegment) GetRemoteIPv6Address() []byte {
	return append([]byte(nil), tg.remoteIPv6Address...)
}

// GetSID returns the optional SR-MPLS SID and whether it is present
func (tg *typeGSegment) GetSID() (uint32, bool) {
	if tg.sid != nil {
		return *tg.sid, true
	}
	return 0, false
}

func (tg *typeGSegment) MarshalJSON() ([]byte, error) {
	v := struct {
		SegmentType       SegmentType   `json:"segment_type,omitempty"`
		Flags             *SegmentFlags `json:"flags,omitempty"`
		LocalInterfaceID  uint32        `json:"local_interface_id,omitempty"`
		LocalIPv6Address  []byte        `json:"local_ipv6_address,omitempty"`
		RemoteInterfaceID uint32        `json:"remote_interface_id,omitempty"`
		RemoteIPv6Address []byte        `json:"remote_ipv6_address,omitempty"`
		SID               *uint32       `json:"sid,omitempty"`
	}{
		SegmentType:       TypeG,
		Flags:             tg.flags,
		LocalInterfaceID:  tg.localInterfaceID,
		LocalIPv6Address:  tg.localIPv6Address,
		RemoteInterfaceID: tg.remoteInterfaceID,
		RemoteIPv6Address: tg.remoteIPv6Address,
		SID:               tg.sid,
	}
	return json.Marshal(v)
}

func (tg *typeGSegment) unmarshalJSONObj(objmap map[string]json.RawMessage) error {
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &tg.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["local_interface_id"]; ok {
		if err := json.Unmarshal(b, &tg.localInterfaceID); err != nil {
			return err
		}
	}
	if b, ok := objmap["local_ipv6_address"]; ok {
		if err := json.Unmarshal(b, &tg.localIPv6Address); err != nil {
			return err
		}
		if len(tg.localIPv6Address) != 16 {
			return fmt.Errorf("invalid local IPv6 address length: got %d bytes, want 16", len(tg.localIPv6Address))
		}
	}
	if b, ok := objmap["remote_interface_id"]; ok {
		if err := json.Unmarshal(b, &tg.remoteInterfaceID); err != nil {
			return err
		}
	}
	if b, ok := objmap["remote_ipv6_address"]; ok {
		if err := json.Unmarshal(b, &tg.remoteIPv6Address); err != nil {
			return err
		}
		if len(tg.remoteIPv6Address) != 16 {
			return fmt.Errorf("invalid remote IPv6 address length: got %d bytes, want 16", len(tg.remoteIPv6Address))
		}
	}
	if b, ok := objmap["sid"]; ok {
		var sid uint32
		if err := json.Unmarshal(b, &sid); err != nil {
			return err
		}
		tg.sid = &sid
	}
	return nil
}

func (tg *typeGSegment) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	return tg.unmarshalJSONObj(objmap)
}

// UnmarshalTypeGSegment instantiates an instance of Type G Segment sub tlv (IPv6 link-local adjacency with interface IDs + optional SID)
func UnmarshalTypeGSegment(b []byte) (Segment, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Type G Segment STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 42 && len(b) != 46 {
		return nil, fmt.Errorf("invalid length of Type G Segment STLV: got %d, expected 42 or 46", len(b))
	}
	s := &typeGSegment{}
	p := 0
	s.flags = NewSegmentFlags(b[p])
	p++
	// Skip reserved byte per RFC 9831
	p++
	// Local Interface ID is 4 bytes
	s.localInterfaceID = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	// Local IPv6 address is 16 bytes
	s.localIPv6Address = make([]byte, 16)
	copy(s.localIPv6Address, b[p:p+16])
	p += 16
	// Remote Interface ID is 4 bytes
	s.remoteInterfaceID = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	// Remote IPv6 address is 16 bytes
	s.remoteIPv6Address = make([]byte, 16)
	copy(s.remoteIPv6Address, b[p:p+16])
	p += 16
	// Optional SID (4 bytes) if length is 46
	if len(b) == 46 {
		sid := binary.BigEndian.Uint32(b[p : p+4])
		s.sid = &sid
	}

	return s, nil
}
// TypeHSegment defines methods to access Type H specific elements (IPv6 Local/Remote adjacency + optional MPLS SID)
type TypeHSegment interface {
	GetLocalIPv6Address() []byte
	GetRemoteIPv6Address() []byte
	GetSID() (uint32, bool)
}

type typeHSegment struct {
	flags             *SegmentFlags
	localIPv6Address  []byte
	remoteIPv6Address []byte
	sid               *uint32
}

var _ Segment = &typeHSegment{}
var _ TypeHSegment = &typeHSegment{}

// GetFlags returns the segment flags.
func (th *typeHSegment) GetFlags() *SegmentFlags {
	return th.flags
}

// GetType returns the segment type identifier.
func (th *typeHSegment) GetType() SegmentType {
	return TypeH
}

// GetLocalIPv6Address returns a 16-byte copy of the local IPv6 address safe for modification.
func (th *typeHSegment) GetLocalIPv6Address() []byte {
	return append([]byte(nil), th.localIPv6Address...)
}

// GetRemoteIPv6Address returns a 16-byte copy of the remote IPv6 address safe for modification.
func (th *typeHSegment) GetRemoteIPv6Address() []byte {
	return append([]byte(nil), th.remoteIPv6Address...)
}

// GetSID returns the optional MPLS SID value and whether it is present.
func (th *typeHSegment) GetSID() (uint32, bool) {
	if th.sid != nil {
		return *th.sid, true
	}
	return 0, false
}

func (th *typeHSegment) MarshalJSON() ([]byte, error) {
	v := struct {
		SegmentType       SegmentType   `json:"segment_type,omitempty"`
		Flags             *SegmentFlags `json:"flags,omitempty"`
		LocalIPv6Address  []byte        `json:"local_ipv6_address,omitempty"`
		RemoteIPv6Address []byte        `json:"remote_ipv6_address,omitempty"`
		SID               *uint32       `json:"sid,omitempty"`
	}{
		SegmentType:       TypeH,
		Flags:             th.flags,
		LocalIPv6Address:  th.localIPv6Address,
		RemoteIPv6Address: th.remoteIPv6Address,
		SID:               th.sid,
	}
	return json.Marshal(v)
}

func (th *typeHSegment) unmarshalJSONObj(objmap map[string]json.RawMessage) error {
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &th.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["local_ipv6_address"]; ok {
		if err := json.Unmarshal(b, &th.localIPv6Address); err != nil {
			return err
		}
		if len(th.localIPv6Address) != 16 {
			return fmt.Errorf("local_ipv6_address must be exactly 16 bytes, got %d", len(th.localIPv6Address))
		}
	}
	if b, ok := objmap["remote_ipv6_address"]; ok {
		if err := json.Unmarshal(b, &th.remoteIPv6Address); err != nil {
			return err
		}
		if len(th.remoteIPv6Address) != 16 {
			return fmt.Errorf("remote_ipv6_address must be exactly 16 bytes, got %d", len(th.remoteIPv6Address))
		}
	}
	if b, ok := objmap["sid"]; ok {
		if err := json.Unmarshal(b, &th.sid); err != nil {
			return err
		}
	}
	return nil
}

func (th *typeHSegment) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	return th.unmarshalJSONObj(objmap)
}

// UnmarshalTypeHSegment instantiates an instance of Type H Segment sub tlv (IPv6 Local/Remote adjacency + optional MPLS SID)
func UnmarshalTypeHSegment(b []byte) (Segment, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Type H Segment STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 34 && len(b) != 38 {
		return nil, fmt.Errorf("invalid length of Type H Segment STLV: got %d, expected 34 or 38", len(b))
	}
	s := &typeHSegment{}
	p := 0
	s.flags = NewSegmentFlags(b[p])
	p++
	// Skip reserved byte per RFC 9831
	p++
	// Local IPv6 address is 16 bytes
	s.localIPv6Address = make([]byte, 16)
	copy(s.localIPv6Address, b[p:p+16])
	p += 16
	// Remote IPv6 address is 16 bytes
	s.remoteIPv6Address = make([]byte, 16)
	copy(s.remoteIPv6Address, b[p:p+16])
	p += 16
	// Optional MPLS SID (4 bytes) if length is 38
	if len(b) == 38 {
		sid := binary.BigEndian.Uint32(b[p : p+4])
		s.sid = &sid
	}

	return s, nil
}
// TypeISegment defines methods to access Type I specific elements (IPv6 node address + SR Algorithm + optional SRv6 SID)
type TypeISegment interface {
	GetSRAlgorithm() byte
	GetIPv6NodeAddress() []byte
	GetSRv6SID() ([]byte, bool)
}

type typeISegment struct {
	flags           *SegmentFlags
	srAlgorithm     byte
	ipv6NodeAddress []byte
	srv6SID         []byte
}

var _ Segment = &typeISegment{}
var _ TypeISegment = &typeISegment{}

// GetFlags returns the segment flags.
func (ti *typeISegment) GetFlags() *SegmentFlags {
	return ti.flags
}

// GetType returns the segment type identifier.
func (ti *typeISegment) GetType() SegmentType {
	return TypeI
}

// GetSRAlgorithm returns the SR algorithm byte.
func (ti *typeISegment) GetSRAlgorithm() byte {
	return ti.srAlgorithm
}

// GetIPv6NodeAddress returns a 16-byte copy of the IPv6 node address safe for modification.
func (ti *typeISegment) GetIPv6NodeAddress() []byte {
	return append([]byte(nil), ti.ipv6NodeAddress...)
}

// GetSRv6SID returns a 16-byte copy of the optional SRv6 SID and whether it is present.
func (ti *typeISegment) GetSRv6SID() ([]byte, bool) {
	if ti.srv6SID != nil {
		return append([]byte(nil), ti.srv6SID...), true
	}
	return nil, false
}

func (ti *typeISegment) MarshalJSON() ([]byte, error) {
	v := struct {
		SegmentType     SegmentType   `json:"segment_type,omitempty"`
		Flags           *SegmentFlags `json:"flags,omitempty"`
		SRAlgorithm     byte          `json:"sr_algorithm,omitempty"`
		IPv6NodeAddress []byte        `json:"ipv6_node_address,omitempty"`
		SRv6SID         []byte        `json:"srv6_sid,omitempty"`
	}{
		SegmentType:     TypeI,
		Flags:           ti.flags,
		SRAlgorithm:     ti.srAlgorithm,
		IPv6NodeAddress: ti.ipv6NodeAddress,
		SRv6SID:         ti.srv6SID,
	}
	return json.Marshal(v)
}

func (ti *typeISegment) unmarshalJSONObj(objmap map[string]json.RawMessage) error {
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &ti.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["sr_algorithm"]; ok {
		if err := json.Unmarshal(b, &ti.srAlgorithm); err != nil {
			return err
		}
	}
	if b, ok := objmap["ipv6_node_address"]; ok {
		if err := json.Unmarshal(b, &ti.ipv6NodeAddress); err != nil {
			return err
		}
		if len(ti.ipv6NodeAddress) != 16 {
			return fmt.Errorf("ipv6_node_address must be exactly 16 bytes, got %d", len(ti.ipv6NodeAddress))
		}
	}
	if b, ok := objmap["srv6_sid"]; ok {
		if err := json.Unmarshal(b, &ti.srv6SID); err != nil {
			return err
		}
		if len(ti.srv6SID) != 16 {
			return fmt.Errorf("srv6_sid must be exactly 16 bytes, got %d", len(ti.srv6SID))
		}
	}
	return nil
}

func (ti *typeISegment) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	return ti.unmarshalJSONObj(objmap)
}

// UnmarshalTypeISegment instantiates an instance of Type I Segment sub tlv (IPv6 node address + SR Algorithm + optional SRv6 SID)
func UnmarshalTypeISegment(b []byte) (Segment, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Type I Segment STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 22 && len(b) != 38 {
		return nil, fmt.Errorf("invalid length of Type I Segment STLV: got %d, expected 22 or 38", len(b))
	}
	s := &typeISegment{}
	p := 0
	s.flags = NewSegmentFlags(b[p])
	p++
	// SR Algorithm is 1 byte
	s.srAlgorithm = b[p]
	p++
	// IPv6 node address is 16 bytes
	s.ipv6NodeAddress = make([]byte, 16)
	copy(s.ipv6NodeAddress, b[p:p+16])
	p += 16
	// Skip SRv6 Endpoint Behavior (2 bytes) + Behavior Flags (1 byte) + Reserved (1 byte) per RFC 9831
	p += 4
	// Optional SRv6 SID (16 bytes) if length is 38
	if len(b) == 38 {
		s.srv6SID = make([]byte, 16)
		copy(s.srv6SID, b[p:p+16])
	}

	return s, nil
}
// TypeJSegment defines methods to access Type J specific elements (IPv6 link-local adjacency with interface IDs + SR Algorithm + optional SRv6 SID)
type TypeJSegment interface {
	GetSRAlgorithm() byte
	GetLocalInterfaceID() uint32
	GetLocalIPv6Address() []byte
	GetRemoteInterfaceID() uint32
	GetRemoteIPv6Address() []byte
	GetSRv6SID() ([]byte, bool)
}

type typeJSegment struct {
	flags             *SegmentFlags
	srAlgorithm       byte
	localInterfaceID  uint32
	localIPv6Address  []byte
	remoteInterfaceID uint32
	remoteIPv6Address []byte
	srv6SID           []byte
}

var _ Segment = &typeJSegment{}
var _ TypeJSegment = &typeJSegment{}

// GetFlags returns the segment flags.
func (tj *typeJSegment) GetFlags() *SegmentFlags {
	return tj.flags
}

// GetType returns the segment type identifier.
func (tj *typeJSegment) GetType() SegmentType {
	return TypeJ
}

// GetSRAlgorithm returns the SR algorithm byte.
func (tj *typeJSegment) GetSRAlgorithm() byte {
	return tj.srAlgorithm
}

// GetLocalInterfaceID returns the local interface identifier.
func (tj *typeJSegment) GetLocalInterfaceID() uint32 {
	return tj.localInterfaceID
}

// GetLocalIPv6Address returns a 16-byte copy of the local IPv6 address safe for modification.
func (tj *typeJSegment) GetLocalIPv6Address() []byte {
	return append([]byte(nil), tj.localIPv6Address...)
}

// GetRemoteInterfaceID returns the remote interface identifier.
func (tj *typeJSegment) GetRemoteInterfaceID() uint32 {
	return tj.remoteInterfaceID
}

// GetRemoteIPv6Address returns a 16-byte copy of the remote IPv6 address safe for modification.
func (tj *typeJSegment) GetRemoteIPv6Address() []byte {
	return append([]byte(nil), tj.remoteIPv6Address...)
}

// GetSRv6SID returns a 16-byte copy of the optional SRv6 SID and whether it is present.
func (tj *typeJSegment) GetSRv6SID() ([]byte, bool) {
	if tj.srv6SID != nil {
		return append([]byte(nil), tj.srv6SID...), true
	}
	return nil, false
}

func (tj *typeJSegment) MarshalJSON() ([]byte, error) {
	v := struct {
		SegmentType       SegmentType   `json:"segment_type,omitempty"`
		Flags             *SegmentFlags `json:"flags,omitempty"`
		SRAlgorithm       byte          `json:"sr_algorithm,omitempty"`
		LocalInterfaceID  uint32        `json:"local_interface_id,omitempty"`
		LocalIPv6Address  []byte        `json:"local_ipv6_address,omitempty"`
		RemoteInterfaceID uint32        `json:"remote_interface_id,omitempty"`
		RemoteIPv6Address []byte        `json:"remote_ipv6_address,omitempty"`
		SRv6SID           []byte        `json:"srv6_sid,omitempty"`
	}{
		SegmentType:       TypeJ,
		Flags:             tj.flags,
		SRAlgorithm:       tj.srAlgorithm,
		LocalInterfaceID:  tj.localInterfaceID,
		LocalIPv6Address:  tj.localIPv6Address,
		RemoteInterfaceID: tj.remoteInterfaceID,
		RemoteIPv6Address: tj.remoteIPv6Address,
		SRv6SID:           tj.srv6SID,
	}
	return json.Marshal(v)
}

func (tj *typeJSegment) unmarshalJSONObj(objmap map[string]json.RawMessage) error {
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &tj.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["sr_algorithm"]; ok {
		if err := json.Unmarshal(b, &tj.srAlgorithm); err != nil {
			return err
		}
	}
	if b, ok := objmap["local_interface_id"]; ok {
		if err := json.Unmarshal(b, &tj.localInterfaceID); err != nil {
			return err
		}
	}
	if b, ok := objmap["local_ipv6_address"]; ok {
		if err := json.Unmarshal(b, &tj.localIPv6Address); err != nil {
			return err
		}
		if len(tj.localIPv6Address) != 16 {
			return fmt.Errorf("local_ipv6_address must be exactly 16 bytes, got %d", len(tj.localIPv6Address))
		}
	}
	if b, ok := objmap["remote_interface_id"]; ok {
		if err := json.Unmarshal(b, &tj.remoteInterfaceID); err != nil {
			return err
		}
	}
	if b, ok := objmap["remote_ipv6_address"]; ok {
		if err := json.Unmarshal(b, &tj.remoteIPv6Address); err != nil {
			return err
		}
		if len(tj.remoteIPv6Address) != 16 {
			return fmt.Errorf("remote_ipv6_address must be exactly 16 bytes, got %d", len(tj.remoteIPv6Address))
		}
	}
	if b, ok := objmap["srv6_sid"]; ok {
		if err := json.Unmarshal(b, &tj.srv6SID); err != nil {
			return err
		}
		if len(tj.srv6SID) != 16 {
			return fmt.Errorf("srv6_sid must be exactly 16 bytes, got %d", len(tj.srv6SID))
		}
	}
	return nil
}

func (tj *typeJSegment) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	return tj.unmarshalJSONObj(objmap)
}

// UnmarshalTypeJSegment instantiates an instance of Type J Segment sub tlv (IPv6 link-local adjacency with interface IDs + SR Algorithm + optional SRv6 SID)
func UnmarshalTypeJSegment(b []byte) (Segment, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Type J Segment STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 42 && len(b) != 58 {
		return nil, fmt.Errorf("invalid length of Type J Segment STLV: got %d, expected 42 or 58", len(b))
	}
	s := &typeJSegment{}
	p := 0
	s.flags = NewSegmentFlags(b[p])
	p++
	// SR Algorithm is 1 byte
	s.srAlgorithm = b[p]
	p++
	// Local Interface ID is 4 bytes
	s.localInterfaceID = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	// Local IPv6 address is 16 bytes
	s.localIPv6Address = make([]byte, 16)
	copy(s.localIPv6Address, b[p:p+16])
	p += 16
	// Remote Interface ID is 4 bytes
	s.remoteInterfaceID = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	// Remote IPv6 address is 16 bytes
	s.remoteIPv6Address = make([]byte, 16)
	copy(s.remoteIPv6Address, b[p:p+16])
	p += 16
	// Optional SRv6 SID (16 bytes) if length is 58
	if len(b) == 58 {
		s.srv6SID = make([]byte, 16)
		copy(s.srv6SID, b[p:p+16])
	}

	return s, nil
}
