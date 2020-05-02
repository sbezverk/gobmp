package base

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LinkNLRI defines Node NLRI onject
// https://tools.ietf.org/html/rfc7752#section-3.2
type LinkNLRI struct {
	ProtocolID     uint8
	Identifier     []byte
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
	return tools.ProtocolIDString(l.ProtocolID)
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

// GetLinkID returns Local or Remote Link ID as a string, depending on passed parameter
func (l *LinkNLRI) GetLinkID(local bool) string {
	return l.Link.GetLinkID(local)
}

// GetLinkInterfaceAddr returns Link Interface IPv4 address as a string
func (l *LinkNLRI) GetLinkInterfaceAddr() string {
	ipv4 := l.Link.GetLinkIPv4InterfaceAddr()
	ipv6 := l.Link.GetLinkIPv6InterfaceAddr()
	if ipv4 != "" {
		if ipv6 != "" {
			return ipv4 + "," + ipv6
		}
		return ipv4
	}
	return ipv6
}

// GetLinkNeighborAddr returns Link's neighbor IPv4 address as a string
func (l *LinkNLRI) GetLinkNeighborAddr() string {
	ipv4 := l.Link.GetLinkIPv4NeighborAddr()
	ipv6 := l.Link.GetLinkIPv6NeighborAddr()
	if ipv4 != "" {
		if ipv6 != "" {
			return ipv4 + "," + ipv6
		}
		return ipv4
	}
	return ipv6
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
	glog.V(6).Infof("LinkNLRI Raw: %s", tools.MessageHex(b))
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	l := LinkNLRI{}
	p := 0
	l.ProtocolID = b[p]
	p++
	// Skip 3 reserved bytes
	//	p += 3
	l.Identifier = make([]byte, 8)
	copy(l.Identifier, b[p:p+8])
	p += 8
	// Local Node Descriptor
	// Get Node Descriptor's length, skip Node Descriptor Type
	ndl := binary.BigEndian.Uint16(b[p+2 : p+4])
	ln, err := UnmarshalNodeDescriptor(b[p : p+int(ndl)])
	if err != nil {
		return nil, err
	}
	l.LocalNode = ln
	l.LocalNodeHash = fmt.Sprintf("%x", md5.Sum(b[p:p+int(ndl)]))
	// Skip Node Type and Length 4 bytes
	p += 4
	p += int(ndl)
	// Remote Node Descriptor
	// Get Node Descriptor's length, skip Node Descriptor Type
	ndl = binary.BigEndian.Uint16(b[p+2 : p+4])
	rn, err := UnmarshalNodeDescriptor(b[p : p+int(ndl)])
	if err != nil {
		return nil, err
	}
	l.RemoteNode = rn
	l.RemoteNodeHash = fmt.Sprintf("%x", md5.Sum(b[p:p+int(ndl)]))
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
