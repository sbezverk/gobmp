package base

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

const (
	RemoteASNumberType   = 270
	IPv4RemoteASBRIDType = 271
	IPv6RemoteASBRIDType = 272
)

type InterASLinkNLRI struct {
	ProtocolID    ProtoID
	Identifier    [8]byte
	LocalNode     *NodeDescriptor
	Link          *LinkDescriptor
	LocalNodeHash string
	LinkHash      string
}

func (l *InterASLinkNLRI) GetProtocolID() string {
	return ProtocolIDString(l.ProtocolID)
}

func (l *InterASLinkNLRI) GetIdentifier() uint64 {
	return binary.BigEndian.Uint64(l.Identifier[:])
}

func (l *InterASLinkNLRI) GetLocalASBRIPv4() net.IP {
	if tlv, ok := l.LocalNode.SubTLV[1028]; ok {
		return net.IP(tlv.Value).To4()
	}
	return nil
}

func (l *InterASLinkNLRI) GetLocalASBRIPv6() net.IP {
	if tlv, ok := l.LocalNode.SubTLV[1029]; ok && len(tlv.Value) == net.IPv6len {
		return net.IP(tlv.Value).To16()
	}
	return nil
}

func (l *InterASLinkNLRI) GetRemoteASN() uint32 {
	if tlv, ok := l.Link.LinkTLV[RemoteASNumberType]; ok && len(tlv.Value) >= 4 {
		return binary.BigEndian.Uint32(tlv.Value)
	}
	return 0
}

func (l *InterASLinkNLRI) GetRemoteASBRIPv4() net.IP {
	if tlv, ok := l.Link.LinkTLV[IPv4RemoteASBRIDType]; ok {
		return net.IP(tlv.Value).To4()
	}
	return nil
}

func (l *InterASLinkNLRI) GetRemoteASBRIPv6() net.IP {
	if tlv, ok := l.Link.LinkTLV[IPv6RemoteASBRIDType]; ok && len(tlv.Value) == net.IPv6len {
		return net.IP(tlv.Value).To16()
	}
	return nil
}

func UnmarshalInterASLinkNLRI(b []byte) (*InterASLinkNLRI, error) {
	if len(b) < 13 {
		return nil, fmt.Errorf("Inter-AS Link NLRI too short: need protocol, identifier, and Local Node Descriptor")
	}
	l := &InterASLinkNLRI{ProtocolID: ProtoID(b[0])}
	copy(l.Identifier[:], b[1:9])
	p := 9
	if typ := binary.BigEndian.Uint16(b[p : p+2]); typ != LocalNodeDescriptorType {
		return nil, fmt.Errorf("Inter-AS Link NLRI has Node Descriptor type %d, expected 256", typ)
	}
	ndl := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
	if p+4+ndl > len(b) {
		return nil, fmt.Errorf("Inter-AS Link NLRI Local Node Descriptor truncated: need %d bytes, have %d", ndl, len(b)-p-4)
	}
	localNodeBytes := b[p : p+4+ndl]
	localNode, err := UnmarshalNodeDescriptor(localNodeBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid Inter-AS Link Local Node Descriptor: %w", err)
	}
	if err := validateInterASLocalNode(localNode, l.ProtocolID); err != nil {
		return nil, err
	}
	l.LocalNode = localNode
	localHash := md5.Sum(localNodeBytes)
	l.LocalNodeHash = hex.EncodeToString(localHash[:])
	p += 4 + ndl
	if p == len(b) {
		return nil, fmt.Errorf("Inter-AS Link NLRI has no link descriptors")
	}
	link, err := UnmarshalLinkDescriptor(b[p:])
	if err != nil {
		return nil, fmt.Errorf("invalid Inter-AS Link Descriptors: %w", err)
	}
	if err := validateInterASLinkDescriptors(link); err != nil {
		return nil, err
	}
	l.Link = link
	linkHash := md5.Sum(b[p:])
	l.LinkHash = hex.EncodeToString(linkHash[:])
	return l, nil
}

func validateInterASLocalNode(node *NodeDescriptor, protocol ProtoID) error {
	if tlv, ok := node.SubTLV[512]; !ok {
		return fmt.Errorf("Inter-AS Link Local Node Descriptor missing Autonomous System TLV 512")
	} else if tlv.Length != 4 {
		return fmt.Errorf("Inter-AS Link Local Node Descriptor TLV 512 has length %d, expected 4", tlv.Length)
	}
	igpRouterID, ok := node.SubTLV[515]
	if !ok {
		return fmt.Errorf("Inter-AS Link Local Node Descriptor missing IGP Router-ID TLV 515")
	}
	expectedIGPRouterIDLength := uint16(4)
	if protocol == ISISL1 || protocol == ISISL2 {
		expectedIGPRouterIDLength = 6
	}
	if igpRouterID.Length != expectedIGPRouterIDLength {
		return fmt.Errorf("Inter-AS Link Local Node Descriptor TLV 515 has length %d, expected %d", igpRouterID.Length, expectedIGPRouterIDLength)
	}
	if area, ok := node.SubTLV[514]; ok && area.Length != 4 {
		return fmt.Errorf("Inter-AS Link Local Node Descriptor TLV 514 has length %d, expected 4", area.Length)
	}
	ipv4, hasIPv4 := node.SubTLV[1028]
	ipv6, hasIPv6 := node.SubTLV[1029]
	if !hasIPv4 && !hasIPv6 {
		return fmt.Errorf("Inter-AS Link Local Node Descriptor missing IPv4 or IPv6 ASBR Router-ID TLV")
	}
	if hasIPv4 && ipv4.Length != net.IPv4len {
		return fmt.Errorf("Inter-AS Link Local Node Descriptor TLV 1028 has length %d, expected 4", ipv4.Length)
	}
	if hasIPv6 && ipv6.Length != net.IPv6len {
		return fmt.Errorf("Inter-AS Link Local Node Descriptor TLV 1029 has length %d, expected 16", ipv6.Length)
	}
	return nil
}

func validateInterASLinkDescriptors(link *LinkDescriptor) error {
	remoteAS, ok := link.LinkTLV[RemoteASNumberType]
	if !ok {
		return fmt.Errorf("Inter-AS Link Descriptors missing Remote AS Number TLV 270")
	}
	if remoteAS.Length != 4 {
		return fmt.Errorf("Inter-AS Link Descriptor TLV 270 has length %d, expected 4", remoteAS.Length)
	}
	ipv4, hasIPv4 := link.LinkTLV[IPv4RemoteASBRIDType]
	ipv6, hasIPv6 := link.LinkTLV[IPv6RemoteASBRIDType]
	if !hasIPv4 && !hasIPv6 {
		return fmt.Errorf("Inter-AS Link Descriptors missing IPv4 or IPv6 Remote ASBR ID TLV")
	}
	if hasIPv4 && ipv4.Length != net.IPv4len {
		return fmt.Errorf("Inter-AS Link Descriptor TLV 271 has length %d, expected 4", ipv4.Length)
	}
	if hasIPv6 && ipv6.Length != net.IPv6len {
		return fmt.Errorf("Inter-AS Link Descriptor TLV 272 has length %d, expected 16", ipv6.Length)
	}
	lengths := map[uint16]uint16{258: 8, 259: 4, 260: 4, 261: 16, 262: 16}
	for typ, expected := range lengths {
		if tlv, ok := link.LinkTLV[typ]; ok && tlv.Length != expected {
			return fmt.Errorf("Inter-AS Link Descriptor TLV %d has length %d, expected %d", typ, tlv.Length, expected)
		}
	}
	return nil
}
