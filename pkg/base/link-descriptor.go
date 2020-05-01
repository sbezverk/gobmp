package base

import (
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LinkDescriptor defines Link Descriptor object
// https://tools.ietf.org/html/rfc7752#section-3.2.2
type LinkDescriptor struct {
	LinkTLV map[uint16]TLV
}

// GetLinkID returns Local or Remote Link ID as a string, depending on passed parameter
func (l *LinkDescriptor) GetLinkID(local bool) string {
	if tlv, ok := l.LinkTLV[258]; ok {
		id, err := UnmarshalLocalRemoteIdentifierTLV(tlv.Value)
		if err != nil {
			return ""
		}
		if id == nil {
			return ""
		}
		return id.GetLinkID(local)
	}

	return ""
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

// UnmarshalLinkDescriptor build Link Descriptor object
func UnmarshalLinkDescriptor(b []byte) (*LinkDescriptor, error) {
	glog.V(6).Infof("LinkDescriptor Raw: %s", tools.MessageHex(b))
	ld := LinkDescriptor{}
	p := 0
	ltlv, err := UnmarshalTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	ld.LinkTLV = ltlv

	return &ld, nil
}
