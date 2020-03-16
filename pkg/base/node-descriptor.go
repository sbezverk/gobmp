package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// NodeDescriptor defines Node Descriptor object
// https://tools.ietf.org/html/rfc7752#section-3.2.1
type NodeDescriptor struct {
	Type   uint16
	Length uint16
	SubTLV []NodeDescriptorSubTLV
}

func (nd *NodeDescriptor) String() string {
	var s string

	s += "Node Descriptor TLVs:" + "\n"
	switch nd.Type {
	case 256:
		s += fmt.Sprintf("   Node Descriptor Type: %d (Local Node Descriptors)\n", nd.Type)
	case 257:
		s += fmt.Sprintf("   Node Descriptor Type: %d (Remote Node Descriptors)\n", nd.Type)
	default:
		s += fmt.Sprintf("   Node Descriptor Type: %d\n", nd.Type)
		s += fmt.Sprintf("   Node Descriptor Length: %d\n", nd.Length)
	}
	for _, stlv := range nd.SubTLV {
		s += stlv.String()
	}

	return s
}

// UnmarshalNodeDescriptor build Node Descriptor object
func UnmarshalNodeDescriptor(b []byte) (*NodeDescriptor, error) {
	glog.V(6).Infof("NodeDescriptor Raw: %s", internal.MessageHex(b))
	nd := NodeDescriptor{}
	p := 0
	nd.Type = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	nd.Length = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	stlv, err := UnmarshalNodeDescriptorSubTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	nd.SubTLV = stlv

	return &nd, nil
}
