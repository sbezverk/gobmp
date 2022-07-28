package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// NodeNLRI defines Node NLRI onject
// https://tools.ietf.org/html/rfc7752#section-3.2
type NodeNLRI struct {
	ProtocolID ProtoID
	Identifier []byte `json:"domain_id,omitempty"`
	LocalNode  *NodeDescriptor
}

// GetAllAttribute returns a slice with all attribute types found in Node NLRI object
func (n *NodeNLRI) GetAllAttribute() []uint16 {
	attrs := make([]uint16, 0)
	for _, attr := range n.LocalNode.SubTLV {
		attrs = append(attrs, attr.Type)
	}

	return attrs
}

// GetNodeProtocolID returns a string representation of NodeNLRI ProtocolID field
func (n *NodeNLRI) GetNodeProtocolID() string {
	return ProtocolIDString(n.ProtocolID)
}

// GetIdentifier returns value of Identifier as int64
func (n *NodeNLRI) GetIdentifier() int64 {
	return int64(binary.BigEndian.Uint64(n.Identifier))
}

// GetNodeLSID returns a value of Node Descriptor TLV BGP-LS Identifier
func (n *NodeNLRI) GetNodeLSID() uint32 {
	return n.LocalNode.GetLSID()
}

// GetNodeIGPRouterID returns a value of Node Descriptor TLV IGP Router ID
func (n *NodeNLRI) GetNodeIGPRouterID() string {
	return n.LocalNode.GetIGPRouterID()
}

// GetNodeASN returns Autonomous System Number used to uniqely identify BGP-LS domain
func (n *NodeNLRI) GetNodeASN() uint32 {
	return n.LocalNode.GetASN()
}

// GetNodeOSPFAreaID returns OSPF Area-ID found in Node Descriptor sub tlv
func (n *NodeNLRI) GetNodeOSPFAreaID() string {
	return n.LocalNode.GetOSPFAreaID()
}

// UnmarshalNodeNLRI builds Node NLRI object
func UnmarshalNodeNLRI(b []byte) (*NodeNLRI, error) {
	if glog.V(6) {
		glog.Infof("NodeNLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	n := NodeNLRI{}
	p := 0
	n.ProtocolID = ProtoID(b[p])
	p++

	n.Identifier = make([]byte, 8)
	copy(n.Identifier, b[p:p+8])
	p += 8
	// Local Node Descriptor
	ln, err := UnmarshalNodeDescriptor(b[p:])
	if err != nil {
		return nil, err
	}
	n.LocalNode = ln

	return &n, nil
}
