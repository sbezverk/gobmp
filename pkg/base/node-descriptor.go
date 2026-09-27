package base

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

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

// GetASN returns Autonomous System Number used to uniquely identify BGP-LS domain
func (nd *NodeDescriptor) GetASN() uint32 {
	if tlv, ok := nd.SubTLV[512]; ok && len(tlv.Value) >= 4 {
		return binary.BigEndian.Uint32(tlv.Value)
	}
	return 0
}

// GetLSID returns BGP-LS Identifier found in Node Descriptor sub tlv
func (nd *NodeDescriptor) GetLSID() uint32 {
	if tlv, ok := nd.SubTLV[513]; ok && len(tlv.Value) >= 4 {
		return binary.BigEndian.Uint32(tlv.Value)
	}
	return 0
}

// GetOSPFAreaID returns OSPF Area-ID found in Node Descriptor sub tlv
func (nd *NodeDescriptor) GetOSPFAreaID() string {
	if tlv, ok := nd.SubTLV[514]; ok && len(tlv.Value) >= 4 {
		return strconv.Itoa(int(binary.BigEndian.Uint32(tlv.Value)))
	}
	return ""
}

// GetIGPRouterID returns a value of Node Descriptor sub TLV IGP Router ID
//
// Per RFC 9552 Section 5.2.1.4, the IGP Router-ID length identifies the node
// type: "For an IS-IS non-pseudonode, this contains a 6-octet ISO Node-ID
// ... For an IS-IS pseudonode ... the 6-octet ISO Node-ID of the [DIS]
// followed by a 1-octet, nonzero PSN identifier (7 octets in total). For an
// OSPFv2 or OSPFv3 non-pseudonode, this contains the 4-octet Router-ID. For
// an OSPFv2 pseudonode ... the 4-octet Router-ID of the [DR] followed by the
// 4-octet IPv4 address of the DR's interface to the LAN (8 octets in
// total)." For Direct or Static configuration the value "SHOULD be taken
// from an IPv4 or IPv6 address", so 16 octets is an IPv6 address. Length is
// discriminated from len(tlv.Value), not the separate tlv.Length field, so
// the two can never disagree.
func (nd *NodeDescriptor) GetIGPRouterID() string {
	tlv, ok := nd.SubTLV[515]
	if !ok {
		return ""
	}
	switch len(tlv.Value) {
	case 4:
		// OSPF non-pseudonode: 4-octet Router-ID.
		return net.IP(tlv.Value).To4().String()
	case 6, 7:
		// IS-IS non-pseudonode ISO Node-ID, or IS-IS pseudonode (ISO Node-ID
		// + 1-octet PSN): hex-encoded, 2-byte groups dot-separated.
		return isisNodeIDHex(tlv.Value)
	case 8:
		// OSPF pseudonode: 4-octet DR Router-ID + 4-octet DR interface IPv4
		// address (OSPFv2) or interface identifier (OSPFv3), rendered
		// "a.b.c.d:e.f.g.h" as in the RFC 9552 Section 5.11 example.
		return net.IP(tlv.Value[0:4]).To4().String() + ":" + net.IP(tlv.Value[4:8]).To4().String()
	case 16:
		// Direct or Static configuration: IPv6 address.
		return net.IP(tlv.Value).String()
	default:
		// Length not defined by RFC 9552: keep the raw value visible rather
		// than dropping the identifier.
		return isisNodeIDHex(tlv.Value)
	}
}

// isisNodeIDHex renders bytes as hex digits grouped 2 bytes at a time and
// dot-separated, the ISO Node-ID format, e.g. "0000.0c00.1234" or
// "0000.0c00.1234.01".
func isisNodeIDHex(b []byte) string {
	var sb strings.Builder
	for p, v := range b {
		fmt.Fprintf(&sb, "%02x", v)
		if (p+1)%2 == 0 && p < len(b)-1 {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

// GetBGPRouterID returns BGP Router ID found in Node Descriptor sub tlv
func (nd *NodeDescriptor) GetBGPRouterID() []byte {
	if tlv, ok := nd.SubTLV[516]; ok {
		return tlv.Value
	}
	return nil
}

// GetConfedMemberASN returns Confederation Member ASN (Member-ASN)
func (nd *NodeDescriptor) GetConfedMemberASN() uint32 {
	if tlv, ok := nd.SubTLV[517]; ok && len(tlv.Value) >= 4 {
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
	stlv, err := UnmarshalTLV(b[p : p+int(l)])
	if err != nil {
		return nil, err
	}
	nd.SubTLV = stlv

	return nd, nil
}
