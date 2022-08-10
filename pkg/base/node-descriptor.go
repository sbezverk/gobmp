package base

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

const (
	// LocalNodeDescriptorType defines a constant for Local Node Descriptor type
	LocalNodeDescriptorType = 256
	// RemoteNodeDescriptorType defines a constant for Remote Node Descriptor type
	RemoteNodeDescriptorType = 257
)

// NodeDescriptor defines Node Descriptor object
// https://tools.ietf.org/html/rfc7752#section-3.2.1
type NodeDescriptor struct {
	SubTLV map[uint16]TLV
}

// GetASN returns Autonomous System Number used to uniqely identify BGP-LS domain
func (nd *NodeDescriptor) GetASN() uint32 {
	if tlv, ok := nd.SubTLV[512]; ok {
		return binary.BigEndian.Uint32(tlv.Value)
	}
	return 0
}

// GetLSID returns BGP-LS Identifier found in Node Descriptor sub tlv
func (nd *NodeDescriptor) GetLSID() uint32 {
	if tlv, ok := nd.SubTLV[513]; ok {
		return binary.BigEndian.Uint32(tlv.Value)
	}
	return 0
}

// GetOSPFAreaID returns OSPF Area-ID found in Node Descriptor sub tlv
func (nd *NodeDescriptor) GetOSPFAreaID() string {
	if tlv, ok := nd.SubTLV[514]; ok {
		return strconv.Itoa(int(binary.BigEndian.Uint32(tlv.Value)))
	}
	return "err"
}

// GetIGPRouterID returns a value of Node Descriptor sub TLV IGP Router ID
func (nd *NodeDescriptor) GetIGPRouterID() string {
	var s string
	i := 0
	if tlv, ok := nd.SubTLV[515]; ok {
		if tlv.Length == 4 {
			return net.IP(tlv.Value).To4().String()
		}
		for p := 0; p < len(tlv.Value); p++ {
			s += fmt.Sprintf("%02x", tlv.Value[p])
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

//GetBGPRouterID returns BGP Router ID found in Node Descriptor sub tlv
func (nd *NodeDescriptor) GetBGPRouterID() []byte {
	if tlv, ok := nd.SubTLV[516]; ok {
		return tlv.Value
	}
	return nil
}

// GetConfedMemberASN returns Confederation Member ASN (Member-ASN)
func (nd *NodeDescriptor) GetConfedMemberASN() uint32 {
	if tlv, ok := nd.SubTLV[517]; ok {
		return binary.BigEndian.Uint32(tlv.Value)
	}
	return 0
}

// UnmarshalNodeDescriptor build Node Descriptor object
func UnmarshalNodeDescriptor(b []byte) (*NodeDescriptor, error) {
	if glog.V(6) {
		glog.Infof("NodeDescriptor Raw: %s", tools.MessageHex(b))
	}
	nd := &NodeDescriptor{}
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to Unmarshal Node Descriptor")
	}
	p := 0
	t := binary.BigEndian.Uint16(b[p : p+2])
	if t != LocalNodeDescriptorType && t != RemoteNodeDescriptorType {
		return nil, fmt.Errorf("invalid type for Node Descriptors object")
	}
	p += 2
	l := binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if int(l)+4 > len(b) {
		return nil, fmt.Errorf("not enough bytes to Unmarshal Node Descriptor")
	}
	stlv, err := UnmarshalTLV(b[p:])
	if err != nil {
		return nil, err
	}
	nd.SubTLV = stlv

	return nd, nil
}
