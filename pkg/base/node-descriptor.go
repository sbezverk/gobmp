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
	Type   uint16
	Length uint16
	SubTLV []NodeDescriptorSubTLV
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

// TODO
// https://tools.ietf.org/id/draft-ietf-idr-bgpls-segment-routing-epe-14.html#rfc.section.4.1
// Add new Node Descriptor's TLV:
// 516 BGP Router Identifier (BGP Router-ID)
// 517 Confederation Member ASN (Member-ASN

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
