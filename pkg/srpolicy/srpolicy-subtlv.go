package srpolicy

import (
	"encoding/binary"

	"github.com/sbezverk/gobmp/pkg/srv6"
)

// TLV defines a structure of sub tlv used to encode the
//   information about the SR Policy Candidate Path.
type TLV struct {
	Preference *Preference `json:"preference_subtlv,omitempty"`
	// BindingSID sub-TLV is used to signal the binding SID related
	// information of the SR Policy candidate path.  The contents of this
	// sub-TLV are used by the SRPM
	BindingSID  BSID           `json:"binding_sid_subtlv,omitempty"`
	SegmentList []*SegmentList `json:"segment_list,omitempty"`
}

// Preference sub-TLV is used to carry the preference of the SR
// Policy candidate path.  The contents of this sub-TLV are used by the
// SRPM.
type Preference struct {
	Flags      byte   `json:"flag,omitempty"`
	Preference uint32 `json:"preference,omitempty"`
}

// BSIDType defines type of BSID value
type BSIDType int

const (
	// NOBSID subtlv does not carry BSID
	NOBSID BSIDType = iota
	// LABELBSID subtlv carries Label as BSID
	LABELBSID
	// SRV6BSID subtlv carries SRv6 as BSID
	SRV6BSID
)

// BSID defines methods to get type and value of different types of Binding SID
type BSID interface {
	GetFlag() byte
	GetType() BSIDType
	GetBSID() []byte
}

// noBSID defines structure when Binding SID sub tlv carries no SID
type noBSID struct {
	flags byte
}

func (n *noBSID) GetFlag() byte {
	return n.flags
}
func (n *noBSID) GetType() BSIDType {
	return NOBSID
}
func (n *noBSID) GetBSID() []byte {
	return nil
}

// labelBSID defines structure when Binding SID sub tlv carries a label as Binding SID
type labelBSID struct {
	flags byte
	bsid  uint32
}

func (l *labelBSID) GetFlag() byte {
	return l.flags
}
func (l *labelBSID) GetType() BSIDType {
	return LABELBSID
}
func (l *labelBSID) GetBSID() []byte {
	bsid := make([]byte, 4)
	binary.BigEndian.PutUint32(bsid, l.bsid)
	return bsid
}

// SRv6BSID defines SRv6 BSID specific method
type SRv6BSID interface {
	GetEndpointBehavior() *srv6.EndpointBehavior
}

// srv6BSID defines structure when Binding SID sub tlv carries a srv6 as Binding SID
type srv6BSID struct {
	flag byte
	bsid []byte
	eb   *srv6.EndpointBehavior
}

func (s *srv6BSID) GetFlag() byte {
	return s.flag
}
func (s *srv6BSID) GetType() BSIDType {
	return SRV6BSID
}
func (s *srv6BSID) GetBSID() []byte {
	return s.bsid
}
func (s *srv6BSID) GetEndpointBehavior() *srv6.EndpointBehavior {
	return s.eb
}

// SegmentType defines a type of Segment in Segment List
type SegmentType int

const (
	// TypeA Segment Sub-TLV encodes a single SR-MPLS SID
	TypeA SegmentType = iota
	// TypeB Segment Sub-TLV encodes a single SRv6 SID
	TypeB
	// TypeC Segment Sub-TLV encodes an IPv4 node address, SR Algorithm
	// and an optional SR-MPLS SID
	TypeC
	// TypeD Segment Sub-TLV encodes an IPv6 node address, SR Algorithm
	// and an optional SR-MPLS SID.
	TypeD
	// TypeE Segment Sub-TLV encodes an IPv4 node address, a local
	// interface Identifier (Local Interface ID) and an optional SR-MPLS
	// SID.
	TypeE
	// TypeF Segment Sub-TLV encodes an adjacency local address, an
	// adjacency remote address and an optional SR-MPLS SID.
	TypeF
	// TypeG Segment Sub-TLV encodes an IPv6 Link Local adjacency with
	// IPv6 local node address, a local interface identifier (Local
	// Interface ID), IPv6 remote node address , a remote interface
	// identifier (Remote Interface ID) and an optional SR-MPLS SID.
	TypeG
	// TypeH Segment Sub-TLV encodes an adjacency local address, an
	// adjacency remote address and an optional SR-MPLS SID.
	TypeH
	// TypeI Segment Sub-TLV encodes an IPv6 node address, SR Algorithm
	// and an optional SRv6 SID.
	TypeI
	// TypeJ Segment Sub-TLV encodes an IPv6 Link Local adjacency with
	// local node address, a local interface identifier (Local Interface
	// ID), remote IPv6 node address, a remote interface identifier (Remote
	// Interface ID) and an optional SRv6 SID.
	TypeJ
	// TypeK Segment Sub-TLV encodes an adjacency local address, an
	// adjacency remote address and an optional SRv6 SID.
	TypeK
)

// Weight sub-TLV specifies the weight associated to a given segment
// list.
type Weight struct {
	Flags  byte
	Weight uint32
}

// Segment sub-TLV describes a single segment in a segment list (i.e.,
// a single element of the explicit path).  One or more Segment sub-TLVs
// constitute an explicit path of the SR Policy candidate path.
type Segment interface {
	GetType()
}

// SegmentList sub-TLV encodes a single explicit path towards the
// endpoint.
type SegmentList struct {
	Weight  *Weight   `json:"weight,omitempty"`
	Segment []Segment `json:"segment,omitempty"`
}

// SegmentFlags defines flags a Segment of Segment list can carry
type SegmentFlags struct {
	Vflag bool `json:"v_flag,omitempty"`
	Aflag bool `json:"a_flag,omitempty"`
	Sflag bool `json:"s_flag,omitempty"`
	Bflag bool `json:"b_flag,omitempty"`
}

// ENLP (Explicit NULL Label Policy) sub-TLV is used to indicate
// whether an Explicit NULL Label [RFC3032] must be pushed on an
// unlabeled IP packet before any other labels.
type ENLP struct {
	Flags byte `json:"flags,omitempty"`
	ENLP  byte `json:"enlp,omitempty"`
}

// Priority indicate the order
// in which the SR policies are re-computed upon topological change.
type Priority struct {
	Priority byte `json:"priority,omitempty"`
}

// PathName is used to attach a symbolic name to the SR Policy candidate path.
type PathName struct {
	PathName string
}

//PolicyName is a sub-TLV to associate a symbolic
// name with the SR Policy for which the candidate path is being
// advertised via the SR Policy NLRI.
type PolicyName struct {
	PolicyName string
}
