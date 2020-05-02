package base

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PrefixNLRI defines Prefix NLRI onject
// https://tools.ietf.org/html/rfc7752#section-3.2
type PrefixNLRI struct {
	ProtocolID    uint8
	Identifier    []byte
	LocalNode     *NodeDescriptor
	Prefix        *PrefixDescriptor
	LocalNodeHash string
	IsIPv4        bool
}

// GetAllAttribute returns a slice with all attribute types found in Prefix NLRI object
func (p *PrefixNLRI) GetAllAttribute() []uint16 {
	attrs := make([]uint16, 0)
	for _, attr := range p.LocalNode.SubTLV {
		attrs = append(attrs, attr.Type)
	}

	for _, attr := range p.Prefix.PrefixTLV {
		attrs = append(attrs, attr.Type)
	}

	return attrs
}

// GetPrefixProtocolID returns a string representation of Prefix NLRI ProtocolID field
func (p *PrefixNLRI) GetPrefixProtocolID() string {
	return tools.ProtocolIDString(p.ProtocolID)
}

// GetPrefixASN returns Autonomous System Number used to uniquely identify BGP-LS domain
func (p *PrefixNLRI) GetPrefixASN() uint32 {
	return p.LocalNode.GetASN()
}

// GetPrefixOSPFAreaID returns OSPF Area-ID found in Prefix Descriptor sub tlv
func (p *PrefixNLRI) GetPrefixOSPFAreaID() string {
	return p.LocalNode.GetOSPFAreaID()
}

// GetPrefixLSID returns a value of Prefix Descriptor TLV BGP-LS Identifier
func (p *PrefixNLRI) GetPrefixLSID() uint32 {
	return p.LocalNode.GetLSID()
}

// GetLocalIGPRouterID returns value of Local node IGP router id
func (p *PrefixNLRI) GetLocalIGPRouterID() string {
	return p.LocalNode.GetIGPRouterID()
}

// GetLocalASN returns value of Local Node's ASN
func (p *PrefixNLRI) GetLocalASN() uint32 {
	return p.LocalNode.GetASN()
}

// UnmarshalPrefixNLRI builds Prefix NLRI object
func UnmarshalPrefixNLRI(b []byte, ipv4 bool) (*PrefixNLRI, error) {
	glog.V(6).Infof("PrefixNLRI Raw: %s", tools.MessageHex(b))
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	pr := PrefixNLRI{
		IsIPv4: ipv4,
	}
	p := 0
	pr.ProtocolID = b[p]
	p++
	pr.Identifier = make([]byte, 8)
	copy(pr.Identifier, b[p:p+8])
	p += 8

	// Get Node Descriptor's length, skip Node Descriptor Type
	ndl := binary.BigEndian.Uint16(b[p+2 : p+4])
	ln, err := UnmarshalNodeDescriptor(b[p : p+int(ndl)])
	if err != nil {
		return nil, err
	}
	pr.LocalNode = ln
	pr.LocalNodeHash = fmt.Sprintf("%x", md5.Sum(b[p:p+int(ndl)]))
	// Skip Node Descriptor Type and Length 4 bytes
	p += 4
	p += int(ndl)
	pn, err := UnmarshalPrefixDescriptor(b[p:])
	if err != nil {
		return nil, err
	}
	pr.Prefix = pn

	return &pr, nil
}
