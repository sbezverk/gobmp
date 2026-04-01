package base

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// ProtoID defines a type for Protocol ID field
type ProtoID uint8

const (
	// ISISL1 defines protocol id value for ISIS Level 1
	ISISL1 ProtoID = 1
	// ISISL2 defines protocol id value for ISIS Level 2
	ISISL2 ProtoID = 2
	// OSPFv2 defines protocol id value for OSPFv2
	OSPFv2 ProtoID = 3
	// Direct defines protocol id value for Directly sourced local information
	Direct ProtoID = 4
	// Static defines protocol id value for Statically configuredlocal information
	Static ProtoID = 5
	// OSPFv3 defines protocol id value for OSPFv3
	OSPFv3 ProtoID = 6
	// BGP defines protocol id value for carrying BGP information from the BGP-LS
	// NLRIs carrying IGP link-state information defined in [RFC7752]
	BGP ProtoID = 7
	// RSVPTE defines protocol id value for RSVP Traffic Engineering
	RSVPTE ProtoID = 8
	// SR defines protocol id value for Segment Routing
	SR ProtoID = 9
)

// PrefixNLRI defines Prefix NLRI onject
// https://tools.ietf.org/html/rfc7752#section-3.2
type PrefixNLRI struct {
	ProtocolID    ProtoID
	Identifier    [8]byte
	LocalNode     *NodeDescriptor
	Prefix        *PrefixDescriptor
	LocalNodeHash string
	IsIPv4        bool
}

// GetPrefixProtocolID returns a string representation of Prefix NLRI ProtocolID field
func (p *PrefixNLRI) GetPrefixProtocolID() string {
	return ProtocolIDString(p.ProtocolID)
}

// GetIdentifier returns value of Identifier as int64
func (p *PrefixNLRI) GetIdentifier() int64 {
	return int64(binary.BigEndian.Uint64(p.Identifier[:]))
}

// GetPrefixASN returns Autonomous System Number used to uniquely identify BGP-LS domain
func (p *PrefixNLRI) GetPrefixASN() uint32 {
	return p.LocalNode.GetASN()
}

// GetPrefixOSPFAreaID returns OSPF Area-ID found in Prefix Descriptor sub tlv
func (p *PrefixNLRI) GetPrefixOSPFAreaID() string {
	return p.LocalNode.GetOSPFAreaID()
}

// GetPrefixLSID returns a value of Prefix Descriptor TLV BGP-LS Identifier
func (p *PrefixNLRI) GetPrefixLSID() uint32 {
	return p.LocalNode.GetLSID()
}

// GetLocalIGPRouterID returns value of Local node IGP router id
func (p *PrefixNLRI) GetLocalIGPRouterID() string {
	return p.LocalNode.GetIGPRouterID()
}

// GetLocalASN returns value of Local Node's ASN
func (p *PrefixNLRI) GetLocalASN() uint32 {
	return p.LocalNode.GetASN()
}

// UnmarshalPrefixNLRI builds Prefix NLRI object
func UnmarshalPrefixNLRI(b []byte, ipv4 bool) (*PrefixNLRI, error) {
	if glog.V(6) {
		glog.Infof("PrefixNLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	pr := PrefixNLRI{
		IsIPv4: ipv4,
	}
	p := 0
	pr.ProtocolID = ProtoID(b[p])
	p++
	if p+8 > len(b) {
		return nil, fmt.Errorf("not enough bytes to Unmarshal Prefix NLRI")
	}
	copy(pr.Identifier[:], b[p:p+8])
	p += 8

	// Get Node Descriptor's length, skip Node Descriptor Type
	if p+4 > len(b) {
		return nil, fmt.Errorf("not enough bytes to Unmarshal Local Node Descriptor")
	}
	ndl := binary.BigEndian.Uint16(b[p+2 : p+4])
	if p+int(ndl)+4 > len(b) {
		return nil, fmt.Errorf("not enough bytes to Unmarshal Local Node Descriptor")
	}
	ln, err := UnmarshalNodeDescriptor(b[p : p+int(ndl)+4])
	if err != nil {
		return nil, err
	}
	pr.LocalNode = ln
	s := md5.Sum(b[p : p+int(ndl)+4])
	pr.LocalNodeHash = hex.EncodeToString(s[:])
	// Skip Node Descriptor Type and Length 4 bytes
	p += 4
	p += int(ndl)
	pn, err := UnmarshalPrefixDescriptor(b[p:])
	if err != nil {
		return nil, err
	}
	pr.Prefix = pn

	return &pr, nil
}

// ProtocolIDString returns string with protocol deacription based on the id
func ProtocolIDString(id ProtoID) string {
	switch id {
	case ISISL1:
		return "IS-IS Level 1"
	case ISISL2:
		return "IS-IS Level 2"
	case OSPFv2:
		return "OSPFv2"
	case Direct:
		return "Direct"
	case Static:
		return "Static configuration"
	case OSPFv3:
		return "OSPFv3"
	case BGP:
		return "BGP"
	case RSVPTE:
		return "RSVP-TE"
	case SR:
		return "Segment Routing"
	default:
		return "Unknown"
	}
}
