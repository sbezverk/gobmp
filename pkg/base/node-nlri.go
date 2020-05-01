package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// NodeNLRI defines Node NLRI onject
// https://tools.ietf.org/html/rfc7752#section-3.2
type NodeNLRI struct {
	ProtocolID uint8
	Identifier []byte
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
	return tools.ProtocolIDString(n.ProtocolID)
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
	glog.V(6).Infof("NodeNLRI Raw: %s", tools.MessageHex(b))
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	n := NodeNLRI{}
	p := 0
	n.ProtocolID = b[p]
	p++

	n.Identifier = make([]byte, 8)
	copy(n.Identifier, b[p:p+8])
	p += 8
	// Local Node Descriptor
	// Get Node Descriptor's length, skip Node Descriptor Type
	ndl := binary.BigEndian.Uint16(b[p+2 : p+4])
	ln, err := UnmarshalNodeDescriptor(b[p : p+int(ndl)])
	if err != nil {
		return nil, err
	}
	n.LocalNode = ln

	return &n, nil
}
