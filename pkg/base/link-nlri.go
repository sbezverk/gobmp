package base

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// LinkNLRI defines Node NLRI onject
// https://tools.ietf.org/html/rfc7752#section-3.2
type LinkNLRI struct {
	ProtocolID     ProtoID
	Identifier     []byte `json:"domain_id,omitempty"`
	LocalNode      *NodeDescriptor
	RemoteNode     *NodeDescriptor
	Link           *LinkDescriptor
	LocalNodeHash  string
	RemoteNodeHash string
	LinkHash       string
}

// GetAllAttribute returns a slice with all attribute types found in Link NLRI object
func (l *LinkNLRI) GetAllAttribute() []uint16 {
	attrs := make([]uint16, 0)
	for _, attr := range l.LocalNode.SubTLV {
		attrs = append(attrs, attr.Type)
	}
	for _, attr := range l.RemoteNode.SubTLV {
		attrs = append(attrs, attr.Type)
	}
	for _, attr := range l.Link.LinkTLV {
		attrs = append(attrs, attr.Type)
	}

	return attrs
}

// GetLinkProtocolID returns a string representation of LinkNLRI ProtocolID field
func (l *LinkNLRI) GetLinkProtocolID() string {
	return ProtocolIDString(l.ProtocolID)
}

// GetIdentifier returns value of Identifier as int64
func (l *LinkNLRI) GetIdentifier() int64 {
	return int64(binary.BigEndian.Uint64(l.Identifier))
}

// GetLinkLSID returns a value of Link Descriptor TLV BGP-LS Identifier
func (l *LinkNLRI) GetLinkLSID(local bool) uint32 {
	if local {
		return l.LocalNode.GetLSID()
	}
	return l.RemoteNode.GetLSID()
}

// GetLinkASN returns Autonomous System Number used to uniquely identify BGP-LS domain
func (l *LinkNLRI) GetLinkASN(local bool) uint32 {
	if local {
		return l.LocalNode.GetASN()
	}
	return l.RemoteNode.GetASN()
}

// GetLinkOSPFAreaID returns OSPF Area-ID found in Link Descriptor sub tlv
func (l *LinkNLRI) GetLinkOSPFAreaID(local bool) string {
	if local {
		return l.LocalNode.GetOSPFAreaID()
	}
	return l.RemoteNode.GetOSPFAreaID()
}

// GetLinkID returns Local and Remote Link ID a slice of int, element 0 carries Local Link ID, element 1 carries Remote Link ID
func (l *LinkNLRI) GetLinkID() ([]uint32, error) {
	return l.Link.GetLinkID()
}

// GetLinkInterfaceAddr returns Link Interface IPv4 address as a string
func (l *LinkNLRI) GetLinkInterfaceAddr() net.IP {
	if a := l.Link.GetLinkIPv4InterfaceAddr(); a != nil {
		return a
	}
	return l.Link.GetLinkIPv6InterfaceAddr()
}

// GetLinkNeighborAddr returns Link's neighbor IPv4 address as a string
func (l *LinkNLRI) GetLinkNeighborAddr() net.IP {
	if a := l.Link.GetLinkIPv4NeighborAddr(); a != nil {
		return a
	}
	return l.Link.GetLinkIPv6NeighborAddr()
}

// GetLocalASN returns value of Local Node's ASN
func (l *LinkNLRI) GetLocalASN() uint32 {
	return l.LocalNode.GetASN()
}

// GetRemoteASN returns value of Remote Node's ASN
func (l *LinkNLRI) GetRemoteASN() uint32 {
	return l.RemoteNode.GetASN()
}

// GetLocalIGPRouterID returns value of Local node IGP router id
func (l *LinkNLRI) GetLocalIGPRouterID() string {
	return l.LocalNode.GetIGPRouterID()
}

// GetRemoteIGPRouterID returns value of Remote node IGP router id
func (l *LinkNLRI) GetRemoteIGPRouterID() string {
	return l.RemoteNode.GetIGPRouterID()
}

// UnmarshalLinkNLRI builds Link NLRI object
func UnmarshalLinkNLRI(b []byte) (*LinkNLRI, error) {
	if glog.V(6) {
		glog.Infof("LinkNLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	l := LinkNLRI{}
	p := 0
	l.ProtocolID = ProtoID(b[p])
	p++
	// Skip 3 reserved bytes
	//	p += 3
	l.Identifier = make([]byte, 8)
	copy(l.Identifier, b[p:p+8])
	p += 8
	// Local Node Descriptor
	// Get Node Descriptor's length, skip Node Descriptor Type
	ndl := binary.BigEndian.Uint16(b[p+2 : p+4])
	ln, err := UnmarshalNodeDescriptor(b[p : p+int(ndl)+4])
	if err != nil {
		return nil, err
	}
	l.LocalNode = ln
	l.LocalNodeHash = fmt.Sprintf("%x", md5.Sum(b[p:p+int(ndl)+4]))
	// Skip Node Type and Length 4 bytes
	p += 4
	p += int(ndl)
	// Remote Node Descriptor
	// Get Node Descriptor's length, skip Node Descriptor Type
	ndl = binary.BigEndian.Uint16(b[p+2 : p+4])
	rn, err := UnmarshalNodeDescriptor(b[p : p+int(ndl)+4])
	if err != nil {
		return nil, err
	}
	l.RemoteNode = rn
	l.RemoteNodeHash = fmt.Sprintf("%x", md5.Sum(b[p:p+int(ndl)+4]))
	p += int(ndl)
	// Skip Node Type and Length 4 bytes
	p += 4
	// Link Descriptor
	ld, err := UnmarshalLinkDescriptor(b[p:])
	if err != nil {
		return nil, err
	}
	l.Link = ld
	l.LinkHash = fmt.Sprintf("%x", md5.Sum(b[p:]))
	return &l, nil
}
