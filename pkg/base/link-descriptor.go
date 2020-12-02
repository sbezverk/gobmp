package base

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LinkDescriptor defines Link Descriptor object
// https://tools.ietf.org/html/rfc7752#section-3.2.2
type LinkDescriptor struct {
	LinkTLV map[uint16]TLV
}

// GetLinkID returns Local and Remote Link ID as a slice of uint32
func (l *LinkDescriptor) GetLinkID() ([]uint32, error) {
	if tlv, ok := l.LinkTLV[258]; ok {
		if tlv.Length < 8 {
			return nil, fmt.Errorf("not enough bytes to decode Local Remote Id TLV")
		}
		return []uint32{binary.BigEndian.Uint32(tlv.Value[:4]), binary.BigEndian.Uint32(tlv.Value[4:])}, nil
	}

	return nil, fmt.Errorf("tlv 258 not found")
}

// GetLinkIPv4InterfaceAddr returns Link Interface IPv4 address as a string
func (l *LinkDescriptor) GetLinkIPv4InterfaceAddr() string {
	if tlv, ok := l.LinkTLV[259]; ok {
		return net.IP(tlv.Value).To4().String()
	}
	return ""
}

// GetLinkIPv4NeighborAddr returns Link's neighbor IPv4 address as a string
func (l *LinkDescriptor) GetLinkIPv4NeighborAddr() string {
	if tlv, ok := l.LinkTLV[260]; ok {
		return net.IP(tlv.Value).To4().String()
	}
	return ""
}

// GetLinkIPv6InterfaceAddr returns Link Interface IPv6 address as a string
func (l *LinkDescriptor) GetLinkIPv6InterfaceAddr() string {
	if tlv, ok := l.LinkTLV[261]; ok {
		return net.IP(tlv.Value).To16().String()
	}
	return ""
}

// GetLinkIPv6NeighborAddr returns Link's neighbor IPv6 address as a string
func (l *LinkDescriptor) GetLinkIPv6NeighborAddr() string {
	if tlv, ok := l.LinkTLV[262]; ok {
		return net.IP(tlv.Value).To16().String()
	}
	return ""
}

// GetLinkMTID returns Link Multi-Topology identifiers
func (l *LinkDescriptor) GetLinkMTID() *MultiTopologyIdentifier {
	if tlv, ok := l.LinkTLV[263]; ok {
		m, err := UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
		if err != nil {
			return nil
		}
		if m == nil {
			return nil
		}
		return m[0]
	}

	return nil
}

// UnmarshalLinkDescriptor build Link Descriptor object
func UnmarshalLinkDescriptor(b []byte) (*LinkDescriptor, error) {
	if glog.V(6) {
		glog.Infof("LinkDescriptor Raw: %s", tools.MessageHex(b))
	}
	ld := LinkDescriptor{}
	p := 0
	ltlv, err := UnmarshalTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	ld.LinkTLV = ltlv

	return &ld, nil
}
