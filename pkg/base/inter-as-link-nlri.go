package base

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

const (
	// RemoteASNumberType identifies the Remote AS Number link descriptor defined by draft-44.
	RemoteASNumberType = 270
	// IPv4RemoteASBRIDType identifies the IPv4 Remote ASBR ID link descriptor.
	IPv4RemoteASBRIDType = 271
	// IPv6RemoteASBRIDType identifies the IPv6 Remote ASBR ID link descriptor.
	IPv6RemoteASBRIDType = 272
)

// InterASLinkNLRI represents one advertised half of an Inter-AS link NLRI.
type InterASLinkNLRI struct {
	ProtocolID    ProtoID
	Identifier    [8]byte
	LocalNode     *NodeDescriptor
	Link          *LinkDescriptor
	LocalNodeHash string
	LinkHash      string
}

// InterASDomainKey identifies an IGP domain using the tuple mandated by draft-44.
type InterASDomainKey struct {
	ASN        uint32 `json:"asn"`
	Identifier uint64 `json:"identifier"`
}

// GetDomainKey returns the local ASN and BGP-LS Instance Identifier used to distinguish the IGP domain.
func (l *InterASLinkNLRI) GetDomainKey() *InterASDomainKey {
	return &InterASDomainKey{ASN: l.LocalNode.GetASN(), Identifier: l.GetIdentifier()}
}

// GetProtocolID returns the textual description of the source protocol.
func (l *InterASLinkNLRI) GetProtocolID() string {
	return ProtocolIDString(l.ProtocolID)
}

// GetIdentifier returns the unsigned 64-bit BGP-LS Instance Identifier.
func (l *InterASLinkNLRI) GetIdentifier() uint64 {
	return binary.BigEndian.Uint64(l.Identifier[:])
}

// GetLocalASBRIPv4 returns the local ASBR IPv4 Router-ID from TLV 1028.
func (l *InterASLinkNLRI) GetLocalASBRIPv4() net.IP {
	if tlv, ok := l.LocalNode.SubTLV[1028]; ok {
		return net.IP(tlv.Value).To4()
	}
	return nil
}

// GetLocalASBRIPv6 returns the local ASBR IPv6 Router-ID from TLV 1029.
func (l *InterASLinkNLRI) GetLocalASBRIPv6() net.IP {
	if tlv, ok := l.LocalNode.SubTLV[1029]; ok && len(tlv.Value) == net.IPv6len {
		return net.IP(tlv.Value).To16()
	}
	return nil
}

// GetRemoteASN returns the neighboring autonomous system from TLV 270.
func (l *InterASLinkNLRI) GetRemoteASN() uint32 {
	if tlv, ok := l.Link.LinkTLV[RemoteASNumberType]; ok && len(tlv.Value) >= 4 {
		return binary.BigEndian.Uint32(tlv.Value)
	}
	return 0
}

// GetRemoteASBRIPv4 returns the neighboring ASBR IPv4 Router-ID from TLV 271.
func (l *InterASLinkNLRI) GetRemoteASBRIPv4() net.IP {
	if tlv, ok := l.Link.LinkTLV[IPv4RemoteASBRIDType]; ok {
		return net.IP(tlv.Value).To4()
	}
	return nil
}

// GetRemoteASBRIPv6 returns the neighboring ASBR IPv6 Router-ID from TLV 272.
func (l *InterASLinkNLRI) GetRemoteASBRIPv6() net.IP {
	if tlv, ok := l.Link.LinkTLV[IPv6RemoteASBRIDType]; ok && len(tlv.Value) == net.IPv6len {
		return net.IP(tlv.Value).To16()
	}
	return nil
}

// UnmarshalInterASLinkNLRI decodes and validates a draft-44 Inter-AS Link NLRI value.
func UnmarshalInterASLinkNLRI(b []byte) (*InterASLinkNLRI, error) {
	// Validate and decode the fixed Protocol-ID, Identifier, and descriptor header.
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
	// Decode the mandatory Local Node Descriptor and retain a stable hash for correlation.
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
	// Decode all remaining Inter-AS Link Descriptors, preserving unknown TLVs in the descriptor map.
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

// validateInterASLocalNode enforces the mandatory local ASBR identity descriptors and their wire lengths.
func validateInterASLocalNode(node *NodeDescriptor, protocol ProtoID) error {
	// The local ASN and protocol-specific IGP Router-ID identify the advertising ASBR.
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
	if area, ok := node.SubTLV[514]; ok {
		if protocol != OSPFv2 && protocol != OSPFv3 {
			return fmt.Errorf("Inter-AS Link Local Node Descriptor contains OSPF Area-ID TLV 514 for non-OSPF Protocol-ID %d", protocol)
		}
		if area.Length != 4 {
			return fmt.Errorf("Inter-AS Link Local Node Descriptor TLV 514 has length %d, expected 4", area.Length)
		}
	}
	// At least one TE Router-ID is required, while dual-stack ASBRs may advertise both.
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

// validateInterASLinkDescriptors enforces remote ASBR identity and fixed-length link descriptor encodings.
func validateInterASLinkDescriptors(link *LinkDescriptor) error {
	// The remote ASN and at least one remote ASBR Router-ID identify the neighboring half-link.
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
	// Validate optional link-correlation descriptors when the source IGP advertises them.
	lengths := map[uint16]uint16{258: 8, 259: 4, 260: 4, 261: 16, 262: 16}
	for typ, expected := range lengths {
		if tlv, ok := link.LinkTLV[typ]; ok && tlv.Length != expected {
			return fmt.Errorf("Inter-AS Link Descriptor TLV %d has length %d, expected %d", typ, tlv.Length, expected)
		}
	}
	return nil
}
