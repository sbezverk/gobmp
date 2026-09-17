package base

import (
	"bytes"
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
	Link          *InterASLinkDescriptors
	LocalNodeHash string
	LinkHash      string
}

// InterASDomainKey identifies an IGP domain using the tuple mandated by draft-44.
type InterASDomainKey struct {
	ASN        uint32 `json:"asn"`
	Identifier int64  `json:"identifier"`
}

// InterASLinkDescriptors preserves Inter-AS Link Descriptor TLVs in canonical wire order.
type InterASLinkDescriptors struct {
	TLVs []TLV `json:"tlvs,omitempty"`
}

// GetAll returns every descriptor of the requested type in wire order.
func (d *InterASLinkDescriptors) GetAll(typ uint16) []TLV {
	if d == nil {
		return nil
	}
	var result []TLV
	for _, tlv := range d.TLVs {
		if tlv.Type == typ {
			result = append(result, tlv)
		}
	}
	return result
}

// GetLinkID returns the local and remote link identifiers from the first TLV 258.
func (d *InterASLinkDescriptors) GetLinkID() ([]uint32, error) {
	tlv, ok := d.first(258)
	if !ok {
		return nil, fmt.Errorf("tlv 258 not found")
	}
	if len(tlv.Value) != 8 {
		return nil, fmt.Errorf("tlv 258 has length %d, expected 8", len(tlv.Value))
	}
	return []uint32{binary.BigEndian.Uint32(tlv.Value[:4]), binary.BigEndian.Uint32(tlv.Value[4:8])}, nil
}

// GetLinkIPv4InterfaceAddr returns the first IPv4 interface address descriptor.
func (d *InterASLinkDescriptors) GetLinkIPv4InterfaceAddr() net.IP {
	return d.ip(259, net.IPv4len)
}

// GetLinkIPv4NeighborAddr returns the first IPv4 neighbor address descriptor.
func (d *InterASLinkDescriptors) GetLinkIPv4NeighborAddr() net.IP {
	return d.ip(260, net.IPv4len)
}

// GetLinkIPv6InterfaceAddr returns the first IPv6 interface address descriptor.
func (d *InterASLinkDescriptors) GetLinkIPv6InterfaceAddr() net.IP {
	return d.ip(261, net.IPv6len)
}

// GetLinkIPv6NeighborAddr returns the first IPv6 neighbor address descriptor.
func (d *InterASLinkDescriptors) GetLinkIPv6NeighborAddr() net.IP {
	return d.ip(262, net.IPv6len)
}

// GetLinkMTID returns the first Multi-Topology Identifier descriptor.
func (d *InterASLinkDescriptors) GetLinkMTID() *MultiTopologyIdentifier {
	tlv, ok := d.first(263)
	if !ok {
		return nil
	}
	mtids, err := UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
	if err != nil || len(mtids) == 0 {
		return nil
	}
	return mtids[0]
}

// first returns the first descriptor of a type from the canonical ordered sequence.
func (d *InterASLinkDescriptors) first(typ uint16) (TLV, bool) {
	if d == nil {
		return TLV{}, false
	}
	for _, tlv := range d.TLVs {
		if tlv.Type == typ {
			return tlv, true
		}
	}
	return TLV{}, false
}

// ip returns the first descriptor value as an IP address when its width matches the address family.
func (d *InterASLinkDescriptors) ip(typ uint16, length int) net.IP {
	tlv, ok := d.first(typ)
	if !ok || len(tlv.Value) != length {
		return nil
	}
	if length == net.IPv4len {
		return net.IP(tlv.Value).To4()
	}
	return net.IP(tlv.Value).To16()
}

// UnmarshalInterASLinkDescriptors decodes descriptors without losing duplicate TLVs or their order.
func UnmarshalInterASLinkDescriptors(b []byte) (*InterASLinkDescriptors, error) {
	tlvs, err := unmarshalCanonicalInterASTLVs(b)
	if err != nil {
		return nil, err
	}
	return &InterASLinkDescriptors{TLVs: tlvs}, nil
}

// unmarshalCanonicalInterASTLVs decodes an RFC 9552 NLRI TLV sequence and rejects non-canonical ordering.
func unmarshalCanonicalInterASTLVs(b []byte) ([]TLV, error) {
	tlvs := make([]TLV, 0)
	for p := 0; p < len(b); {
		if p+4 > len(b) {
			return nil, fmt.Errorf("invalid Inter-AS TLV header at offset %d: have %d bytes", p, len(b)-p)
		}
		tlv := TLV{Type: binary.BigEndian.Uint16(b[p : p+2]), Length: binary.BigEndian.Uint16(b[p+2 : p+4])}
		p += 4
		if p+int(tlv.Length) > len(b) {
			return nil, fmt.Errorf("invalid Inter-AS TLV type %d at offset %d: need %d bytes, have %d", tlv.Type, p-4, tlv.Length, len(b)-p)
		}
		tlv.Value = append([]byte(nil), b[p:p+int(tlv.Length)]...)
		if len(tlvs) > 0 && compareInterASTLV(tlvs[len(tlvs)-1], tlv) > 0 {
			return nil, fmt.Errorf("Inter-AS TLV type %d is not in canonical RFC 9552 order", tlv.Type)
		}
		tlvs = append(tlvs, tlv)
		p += int(tlv.Length)
	}
	return tlvs, nil
}

// compareInterASTLV applies the RFC 9552 type, length, and opaque-value ordering rules.
func compareInterASTLV(a, b TLV) int {
	if a.Type < b.Type {
		return -1
	}
	if a.Type > b.Type {
		return 1
	}
	if a.Length < b.Length {
		return -1
	}
	if a.Length > b.Length {
		return 1
	}
	return bytes.Compare(a.Value, b.Value)
}

// GetDomainKey returns the local ASN and BGP-LS Instance Identifier used to distinguish the IGP domain.
func (l *InterASLinkNLRI) GetDomainKey() *InterASDomainKey {
	if l == nil || l.LocalNode == nil {
		return nil
	}
	return &InterASDomainKey{ASN: l.LocalNode.GetASN(), Identifier: l.GetIdentifier()}
}

// GetProtocolID returns the textual description of the source protocol.
func (l *InterASLinkNLRI) GetProtocolID() string {
	if l == nil {
		return ProtocolIDString(0)
	}
	return ProtocolIDString(l.ProtocolID)
}

// GetIdentifier returns the BGP-LS Instance Identifier using the int64 representation shared by other LS types.
func (l *InterASLinkNLRI) GetIdentifier() int64 {
	if l == nil {
		return 0
	}
	return int64(binary.BigEndian.Uint64(l.Identifier[:]))
}

// GetLocalASBRIPv4 returns the local ASBR IPv4 Router-ID from TLV 1028.
func (l *InterASLinkNLRI) GetLocalASBRIPv4() net.IP {
	if l == nil || l.LocalNode == nil {
		return nil
	}
	if tlv, ok := l.LocalNode.SubTLV[1028]; ok {
		return net.IP(tlv.Value).To4()
	}
	return nil
}

// GetLocalASBRIPv6 returns the local ASBR IPv6 Router-ID from TLV 1029.
func (l *InterASLinkNLRI) GetLocalASBRIPv6() net.IP {
	if l == nil || l.LocalNode == nil {
		return nil
	}
	if tlv, ok := l.LocalNode.SubTLV[1029]; ok && len(tlv.Value) == net.IPv6len {
		return net.IP(tlv.Value).To16()
	}
	return nil
}

// GetRemoteASN returns the neighboring autonomous system from TLV 270.
func (l *InterASLinkNLRI) GetRemoteASN() uint32 {
	if l == nil || l.Link == nil {
		return 0
	}
	if tlv, ok := l.Link.first(RemoteASNumberType); ok && len(tlv.Value) >= 4 {
		return binary.BigEndian.Uint32(tlv.Value)
	}
	return 0
}

// GetRemoteASBRIPv4 returns the neighboring ASBR IPv4 Router-ID from TLV 271.
func (l *InterASLinkNLRI) GetRemoteASBRIPv4() net.IP {
	if l == nil || l.Link == nil {
		return nil
	}
	if tlv, ok := l.Link.first(IPv4RemoteASBRIDType); ok {
		return net.IP(tlv.Value).To4()
	}
	return nil
}

// GetRemoteASBRIPv6 returns the neighboring ASBR IPv6 Router-ID from TLV 272.
func (l *InterASLinkNLRI) GetRemoteASBRIPv6() net.IP {
	if l == nil || l.Link == nil {
		return nil
	}
	if tlv, ok := l.Link.first(IPv6RemoteASBRIDType); ok && len(tlv.Value) == net.IPv6len {
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
	if _, err := unmarshalCanonicalInterASTLVs(localNodeBytes[4:]); err != nil {
		return nil, fmt.Errorf("invalid Inter-AS Link Local Node Descriptor ordering: %w", err)
	}
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
	// Decode all remaining Inter-AS Link Descriptors, preserving duplicate TLVs in canonical wire order.
	link, err := UnmarshalInterASLinkDescriptors(b[p:])
	if err != nil {
		return nil, fmt.Errorf("invalid Inter-AS Link Descriptors: %w", err)
	}
	// Enforce canonical ordering across the Local Node Descriptor and the following link descriptors.
	localTLV := TLV{Type: LocalNodeDescriptorType, Length: uint16(ndl), Value: localNodeBytes[4:]}
	if len(link.TLVs) > 0 && compareInterASTLV(localTLV, link.TLVs[0]) > 0 {
		return nil, fmt.Errorf("Inter-AS Link Descriptors are not in canonical RFC 9552 order after Local Node Descriptor")
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
	if node == nil {
		return fmt.Errorf("Inter-AS Link Local Node Descriptor is nil")
	}
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
func validateInterASLinkDescriptors(link *InterASLinkDescriptors) error {
	if link == nil {
		return fmt.Errorf("Inter-AS Link Descriptors are nil")
	}
	var hasRemoteAS, hasIPv4, hasIPv6 bool
	for _, tlv := range link.TLVs {
		var expected uint16
		switch tlv.Type {
		case 258:
			expected = 8
		case 259, 260, RemoteASNumberType, IPv4RemoteASBRIDType:
			expected = 4
		case 261, 262, IPv6RemoteASBRIDType:
			expected = 16
		default:
			continue
		}
		if tlv.Length != expected {
			return fmt.Errorf("Inter-AS Link Descriptor TLV %d has length %d, expected %d", tlv.Type, tlv.Length, expected)
		}
		switch tlv.Type {
		case RemoteASNumberType:
			hasRemoteAS = true
		case IPv4RemoteASBRIDType:
			hasIPv4 = true
		case IPv6RemoteASBRIDType:
			hasIPv6 = true
		}
	}
	if !hasRemoteAS {
		return fmt.Errorf("Inter-AS Link Descriptors missing Remote AS Number TLV 270")
	}
	if !hasIPv4 && !hasIPv6 {
		return fmt.Errorf("Inter-AS Link Descriptors missing IPv4 or IPv6 Remote ASBR ID TLV")
	}
	return nil
}
