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
				fallthrough
			case TypeC:
				fallthrough
			case TypeD:
				fallthrough
			case TypeE:
				fallthrough
			case TypeF:
				fallthrough
			case TypeG:
				fallthrough
			case TypeH:
				fallthrough
			case TypeI:
				fallthrough
			case TypeJ:
				fallthrough
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
			glog.Infof("Segment of type A")
			l := b[p]
			p++
			if l != 6 {
				return nil, fmt.Errorf("invalid length %d of raw data for Type A Segment Sub TLV", l)
			}
			s, err := UnmarshalTypeASegment(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			sl.Segment = append(sl.Segment, s)
			p += int(l)
		case int(TypeB):
			glog.Infof("Segment of type B not implemented")
		case int(TypeC):
			glog.Infof("Segment of type C not implemented")
		case int(TypeD):
			glog.Infof("Segment of type D not implemented")
		case int(TypeE):
			glog.Infof("Segment of type E not implemented")
		case int(TypeF):
			glog.Infof("Segment of type F not implemented")
		case int(TypeG):
			glog.Infof("Segment of type G not implemented")
		case int(TypeH):
			glog.Infof("Segment of type H not implemented")
		case int(TypeI):
			glog.Infof("Segment of type I not implemented")
		case int(TypeJ):
			glog.Infof("Segment of type J not implemented")
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
