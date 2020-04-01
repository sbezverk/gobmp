package base

import (
	"encoding/binary"
	"encoding/json"
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

func (n *NodeNLRI) String() string {
	var s string
	s += fmt.Sprintf("Protocol ID: %s\n", tools.ProtocolIDString(n.ProtocolID))
	s += fmt.Sprintf("Identifier: %s\n", tools.MessageHex(n.Identifier))
	s += n.LocalNode.String()

	return s
}

// GetProtocolID returns a string representation of NodeNLRI ProtocolID field
func (n *NodeNLRI) GetProtocolID() string {
	return tools.ProtocolIDString(n.ProtocolID)
}

// GetLSID returns a value of Node Descriptor TLV BGP-LS Identifier
func (n *NodeNLRI) GetLSID() uint32 {
	return n.LocalNode.GetLSID()
}

// GetIGPRouterID returns a value of Node Descriptor TLV IGP Router ID
func (n *NodeNLRI) GetIGPRouterID() string {
	return n.LocalNode.GetIGPRouterID()
}

// GetASN returns Autonomous System Number used to uniqely identify BGP-LS domain
func (n *NodeNLRI) GetASN() uint32 {
	return n.LocalNode.GetASN()
}

// GetOSPFAreaID returns OSPF Area-ID found in Node Descriptor sub tlv
func (n *NodeNLRI) GetOSPFAreaID() string {
	return n.LocalNode.GetOSPFAreaID()
}

// MarshalJSON defines a method to Marshal Node NLRI object into JSON format
func (n *NodeNLRI) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"protocolID\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", n.ProtocolID))...)
	jsonData = append(jsonData, []byte("\"identifier\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", n.Identifier))...)
	jsonData = append(jsonData, []byte("\"localNode\":")...)
	if n.LocalNode != nil {
		b, err := json.Marshal(n.LocalNode)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	} else {
		jsonData = append(jsonData, "{}"...)
	}
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalNodeNLRI builds Node NLRI object
func UnmarshalNodeNLRI(b []byte) (*NodeNLRI, error) {
	glog.V(6).Infof("NodeNLRI Raw: %s", tools.MessageHex(b))
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
