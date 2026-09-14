package base

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// LinkNLRI defines Node NLRI onject
// https://tools.ietf.org/html/rfc7752#section-3.2
type LinkNLRI struct {
	ProtocolID     ProtoID
	Identifier     [8]byte
	LocalNode      *NodeDescriptor
	RemoteNode     *NodeDescriptor
	Link           *LinkDescriptor
	LocalNodeHash  string
	RemoteNodeHash string
	LinkHash       string
}

// GetLinkProtocolID returns a string representation of LinkNLRI ProtocolID field
func (l *LinkNLRI) GetLinkProtocolID() string {
	return ProtocolIDString(l.ProtocolID)
}

// GetIdentifier returns value of Identifier as int64
func (l *LinkNLRI) GetIdentifier() int64 {
	return int64(binary.BigEndian.Uint64(l.Identifier[:]))
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
	if p+8 > len(b) {
		return nil, fmt.Errorf("not enough bytes to Unmarshal Link NLRI")
	}
	copy(l.Identifier[:], b[p:p+8])
	p += 8
	// Local Node Descriptor
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
	l.LocalNode = ln
	lnh := md5.Sum(b[p : p+int(ndl)+4])
	l.LocalNodeHash = hex.EncodeToString(lnh[:])
	// Skip Node Type and Length 4 bytes
	p += 4
	p += int(ndl)
	// Remote Node Descriptor
	// Get Node Descriptor's length, skip Node Descriptor Type
	if p+4 > len(b) {
		return nil, fmt.Errorf("not enough bytes to Unmarshal Remote Node Descriptor")
	}
	ndl = binary.BigEndian.Uint16(b[p+2 : p+4])
	if p+int(ndl)+4 > len(b) {
		return nil, fmt.Errorf("not enough bytes to Unmarshal Remote Node Descriptor")
	}
	rn, err := UnmarshalNodeDescriptor(b[p : p+int(ndl)+4])
	if err != nil {
		return nil, err
	}
	l.RemoteNode = rn
	rnh := md5.Sum(b[p : p+int(ndl)+4])
	l.RemoteNodeHash = hex.EncodeToString(rnh[:])
	p += int(ndl)
	// Skip Node Type and Length 4 bytes
	p += 4
	// Link Descriptor
	ld, err := UnmarshalLinkDescriptor(b[p:])
	if err != nil {
		return nil, err
	}
	l.Link = ld
	lkh := md5.Sum(b[p:])
	l.LinkHash = hex.EncodeToString(lkh[:])
	return &l, nil
}
