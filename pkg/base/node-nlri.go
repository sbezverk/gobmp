package base

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// NodeNLRI defines Node NLRI onject
// https://tools.ietf.org/html/rfc7752#section-3.2
type NodeNLRI struct {
	ProtocolID uint8
	Identifier uint64
	LocalNode  *NodeDescriptor
}

func (n *NodeNLRI) String() string {
	var s string
	s += fmt.Sprintf("Protocol ID: %s\n", internal.ProtocolIDString(n.ProtocolID))
	s += fmt.Sprintf("Identifier: %d\n", n.Identifier)
	s += n.LocalNode.String()

	return s
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
	glog.V(6).Infof("NodeNLRI Raw: %s", internal.MessageHex(b))
	n := NodeNLRI{}
	p := 0
	n.ProtocolID = b[p]
	p++

	n.Identifier = binary.BigEndian.Uint64(b[p : p+8])
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
