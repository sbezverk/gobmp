package srpolicy

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
