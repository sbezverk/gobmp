package base

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
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

// GetASN returns Autonomous System Number used to uniqely identify BGP-LS domain
func (nd *NodeDescriptor) GetASN() uint32 {
	for _, tlv := range nd.SubTLV {
		if tlv.Type != 512 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}
	return 0
}

// GetLSID returns BGP-LS Identifier found in Node Descriptor sub tlv
func (nd *NodeDescriptor) GetLSID() uint32 {
	for _, tlv := range nd.SubTLV {
		if tlv.Type != 513 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}
	return 0
}

// GetOSPFAreaID returns OSPF Area-ID found in Node Descriptor sub tlv
func (nd *NodeDescriptor) GetOSPFAreaID() string {
	for _, tlv := range nd.SubTLV {
		if tlv.Type != 514 {
			continue
		}
		return net.IP(tlv.Value).To4().String()
	}
	return ""
}

// GetIGPRouterID returns a value of Node Descriptor sub TLV IGP Router ID
func (nd *NodeDescriptor) GetIGPRouterID() string {
	var s string
	i := 0
	for _, tlv := range nd.SubTLV {
		if tlv.Type != 515 {
			continue
		}
		if tlv.Length == 4 {
			return net.IP(tlv.Value).To4().String()
		}
		for p := 0; p < len(tlv.Value); p++ {
			s += fmt.Sprintf("%02d", tlv.Value[p])
			if i == 1 && p < len(tlv.Value)-1 {
				s += "."
				i = 0
				continue
			}
			i++
		}
		return s
	}

	return s
}

// MarshalJSON defines a method to Marshal Node Descriptor object into JSON format
func (nd *NodeDescriptor) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"Type\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", nd.Type))...)
	jsonData = append(jsonData, []byte("\"Description\":")...)
	switch nd.Type {
	case 256:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Local Node\","))...)
	case 257:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Remote Node\","))...)
	default:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Unknown Node\","))...)
	}
	jsonData = append(jsonData, []byte("\"SubTLV\":")...)
	jsonData = append(jsonData, '[')
	if nd.SubTLV != nil {
		for i, stlv := range nd.SubTLV {
			b, err := json.Marshal(&stlv)
			if err != nil {
				return nil, err
			}
			jsonData = append(jsonData, b...)
			if i < len(nd.SubTLV)-1 {
				jsonData = append(jsonData, ',')
			}
		}
	}
	jsonData = append(jsonData, ']')
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalNodeDescriptor build Node Descriptor object
func UnmarshalNodeDescriptor(b []byte) (*NodeDescriptor, error) {
	glog.V(6).Infof("NodeDescriptor Raw: %s", tools.MessageHex(b))
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
