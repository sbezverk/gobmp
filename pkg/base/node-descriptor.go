package base

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
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
		return net.IP(tlv.Value).To4().String()
	}
	return ""
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

//GetBGPRouterID returns BGP Router ID found in Node Descriptor sub tlv
func (nd *NodeDescriptor) GetBGPRouterID() string {
	if tlv, ok := nd.SubTLV[516]; ok {
		return net.IP(tlv.Value).To4().String()
	}
	return ""
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
	glog.V(6).Infof("NodeDescriptor Raw: %s", tools.MessageHex(b))
	nd := NodeDescriptor{}
	p := 0
	//	nd.Type = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	//	nd.Length = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	stlv, err := UnmarshalTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	nd.SubTLV = stlv

	return &nd, nil
}
