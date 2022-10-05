package bgp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// ExtCommunity defines BGP Extended Commuity
type ExtCommunity struct {
	Type    uint8
	SubType *uint8
	Value   []byte
}

// IsRouteTarget return true is a specific extended community of Route Target type
func (ext *ExtCommunity) IsRouteTarget() bool {
	var subType uint8
	if ext.SubType == nil {
		subType = 0xff
	} else {
		subType = *ext.SubType
	}
	if subType == 2 {
		return true
	}

	return false
}

func makeExtCommunity(b []byte) (*ExtCommunity, error) {
	ext := ExtCommunity{}
	if len(b) != 8 {
		return nil, fmt.Errorf("invalid length expected 8 got %d", len(b))
	}
	p := 0
	ext.Type = b[p]
	p++
	l := 7
	switch ext.Type & 0x3f {
	case 0:
		fallthrough
	case 1:
		fallthrough
	case 2:
		fallthrough
	case 6:
		st := uint8(b[p])
		ext.SubType = &st
		l = 6
		p++
	case 3:
		st := uint8(b[p])
		ext.SubType = &st
		l = 6
		p += 3
	}
	ext.Value = make([]byte, l)
	copy(ext.Value, b[p:])

	return &ext, nil
}

// UnmarshalBGPExtCommunity builds a slice of Extended Communities
func UnmarshalBGPExtCommunity(b []byte) ([]ExtCommunity, error) {
	exts := make([]ExtCommunity, 0)
	for p := 0; p < len(b); {
		if glog.V(6) {
			glog.Infof("Extended community: %s", tools.MessageHex(b[p:p+8]))
		}
		ext, err := makeExtCommunity(b[p : p+8])
		if err != nil {
			return nil, err
		}
		p += 8
		exts = append(exts, *ext)
	}

	return exts, nil
}

// Transitive Two-Octet AS-Specific Extended Community Sub-Types
// 0x02	Route Target	[RFC4360]
// 0x03	Route Origin	[RFC4360]
// 0x05	OSPF Domain Identifier	[RFC4577]
// 0x08	BGP Data Collection	[RFC4384]
// 0x09	Source AS	[RFC6514]
// 0x0a	L2VPN Identifier	[RFC6074]
// 0x10	Cisco VPN-Distinguisher	[Eric_Rosen]
// 0x13	Route-Target Record	[draft-ietf-bess-service-chaining]
// 0x80	Virtual-Network Identifier Extended Community	[Manju_Ramesh]
var transAS2SubTypes = map[uint8]string{
	0x2:  ECPRouteTarget,
	0x3:  ECPRouteOrigin,
	0x5:  ECPOSPFDomainID,
	0x8:  ECPBGPDataCollection,
	0x9:  ECPSourceAS,
	0x0a: ECPL2VPNID,
	0x10: ECPCiscoVPNDistinguisher,
	0x13: ECPRouteTargetRecord,
	0x80: ECPVirtualNetworkID,
}

// Transitive IPv4-Address-Specific Extended Community Sub-Types
// 0x02	Route Target	[RFC4360]
// 0x03	Route Origin	[RFC4360]
// 0x05	OSPF Domain Identifier	[RFC4577]
// 0x07	OSPF Route ID	[RFC4577]
// 0x0a	L2VPN Identifier	[RFC6074]
// 0x0b	VRF Route Import	[RFC6514]
// 0x0c	Flow-spec Redirect to IPv4	[draft-ietf-idr-flowspec-redirect]
// 0x10	Cisco VPN-Distinguisher	[Eric_Rosen]
// 0x12	Inter-Area P2MP Segmented Next-Hop	[RFC7524]
// 0x13	Route-Target Record	[draft-ietf-bess-service-chaining]
// 0x14	VRF-Recursive-Next-Hop-Extended-Community	[Dhananjaya_Rao]
// 0x20	MVPN SA RP-address Extended Community	[draft-zzhang-bess-mvpn-msdp-sa-interoperation]
var transIPv4SubTypes = map[uint8]string{
	0x2:  ECPRouteTarget,
	0x3:  ECPRouteOrigin,
	0x5:  ECPOSPFDomainID,
	0x7:  ECPOSPFRouteID,
	0x0a: ECPL2VPNID,
	0x0b: ECPVRFRouteImport,
	0x0c: ECPFlowSpecRedirIPv4,
	0x10: ECPCiscoVPNDistinguisher,
	0x12: ECPInterAreaP2MPSegmentedNexyHop,
	0x13: ECPRouteTargetRecord,
	0x14: ECPVRFRecursiveNextHop,
	0x20: ECPMVPNSARPAddress,
}

// Transitive Four-Octet AS-Specific Extended Community Sub-Types
// 0x02	Route Target	[RFC5668]
// 0x03	Route Origin	[RFC5668]
// 0x04	Generic (deprecated)	[draft-ietf-idr-as4octet-extcomm-generic-subtype]
// 0x05	OSPF Domain Identifier	[RFC4577]
// 0x08	BGP Data Collection	[RFC4384]
// 0x09	Source AS	[RFC6514]
// 0x10	Cisco VPN Identifier	[Eric_Rosen]
// 0x13	Route-Target Record	[draft-ietf-bess-service-chaining]
var transAS4SubTypes = map[uint8]string{
	0x2:  ECPRouteTarget,
	0x3:  ECPRouteOrigin,
	0x4:  ECPGeneric,
	0x5:  ECPOSPFDomainID,
	0x8:  ECPBGPDataCollection,
	0x9:  ECPSourceAS,
	0x10: ECPCiscoVPNDistinguisher,
	0x13: ECPRouteTargetRecord,
}

// Transitive Opaque Extended Community Sub-Types
// 0x01	Cost Community	[draft-ietf-idr-custom-decision]
// 0x03	CP-ORF	[RFC7543]
// 0x04	Extranet Source Extended Community	[RFC7900]
// 0x05	Extranet Separation Extended Community	[RFC7900]
// 0x06	OSPF Route Type	[RFC4577]
// 0x07	Additional PMSI Tunnel Attribute Flags	[RFC7902]
// 0x08	Context Label Space ID Extended Community	[draft-ietf-bess-mvpn-evpn-aggregation-label]
// 0x0b	Color Extended Community	[RFC5512]
// 0x0c	Encapsulation Extended Community	[RFC5512]
// 0x0d	Default Gateway	[Yakov_Rekhter]
// 0x0e	Point-to-Point-to-Multipoint (PPMP) Label	[Rishabh_Parekh]
// 0x14	Consistent Hash Sort Order	[draft-ietf-bess-service-chaining]
// 0xaa	LoadBalance	[draft-ietf-bess-service-chaining]
var transOpaqueSubTypes = map[uint8]string{
	0x1:  ECPCost,
	0x3:  ECPCPORF,
	0x4:  ECPExtranetSource,
	0x5:  ECPExtranetSeparation,
	0x6:  ECPOSPFRouteType,
	0x7:  ECPAdditionalPMSITunnelAttributeFlags,
	0x8:  ECPContextLabelSpaceID,
	0xb:  ECPColor,
	0xc:  ECPEncapsulation,
	0xd:  ECPDefaultGateway,
	0xe:  ECPPointToPointToMultipoint,
	0x14: ECPConsistentHashSortOrder,
	0xaa: ECPLoadBalance,
}

// EVPN Extended Community Sub-Types
// 0x00	MAC Mobility	[RFC7432]
// 0x01	ESI Label	[RFC7432]
// 0x02	ES-Import Route Target	[RFC7432]
// 0x03	EVPN Router’s MAC Extended Community	[draft-sajassi-l2vpn-evpn-inter-subnet-forwarding]
// 0x04	EVPN Layer 2 Attributes	[RFC8214]
// 0x05	E-Tree Extended Community	[RFC8317]
// 0x06	DF Election Extended Community	[RFC8584]
// 0x07	I-SID Extended Community	[draft-sajassi-bess-evpn-virtual-eth-segment]
// 0x08	ND Extended Community	[draft-snr-bess-evpn-na-flags]
// 0x09	Multicast Flags Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]
// 0x0A	EVI-RT Type 0 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]
// 0x0B	EVI-RT Type 1 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]
// 0x0C	EVI-RT Type 2 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]
// 0x0D	EVI-RT Type 3 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]
// 0x0E	EVPN Attachment Circuit Extended Community	[draft-sajassi-bess-evpn-ac-aware-bundling]
// 0x0F	Service Carving Timestamp	[draft-ietf-bess-evpn-fast-df-recovery-01]
var evpnSubTypes = map[uint8]string{
	0x0: ECPMACMobility,
	0x1: ECPESILabel,
	0x2: ECPESImportRouteTarget,
	0x3: ECPEVPNRouterMAC,
	0x4: ECPEVPNLayer2Attributes,
	0x5: ECPETree,
	0x6: ECPDFElection,
	0x7: ECPISID,
	0x8: ECPND,
	0x9: ECPMulticastFlags,
	0xa: ECPEVIRTType0,
	0xb: ECPEVIRTType1,
	0xc: ECPEVIRTType2,
	0xd: ECPEVIRTType3,
	0xe: ECPEVPNAttachmentCircuit,
	0xf: ECPServiceCarvingTimestamp,
}

// Non-Transitive Two-Octet AS-Specific Extended Community Sub-Types
// 0x04	Link Bandwidth Extended Community	[draft-ietf-idr-link-bandwidth-00]
// 0x80	Virtual-Network Identifier Extended Community	[draft-drao-bgp-l3vpn-virtual-network-overlays]
var nonTransAS2SubTypes = map[uint8]string{
	0x4:  ECPLinkBandwidth,
	0x80: ECPVNIID,
}

// Generic Transitive Experimental Use Extended Community Sub-Types
// 0x06               Flow spec traffic-rate
// 0x07               Flow spec traffic-action (Use of the "Value" field is defined in the "Traffic Action Fields" registry)
// 0x08               Flow spec redirect
// 0x09               Flow spec traffic-remarking
var flowspecSubTypes = map[uint8]string{
	0x6: CPFlowspecTrafficRate,
	0x7: CPFlowspecTrafficAction,
	0x8: CPFlowspecRedirect,
	0x9: CPFlowspecTrafficRemarking,
}

func getSubType(m map[uint8]string, subType uint8) string {
	s := "Subtype unknown="
	var ok bool
	if s, ok = m[subType]; ok {
		return s
	}
	return s
}

// Transitive Two-Octet AS-Specific Extended Community
func type0(subType uint8, value []byte) string {
	return getSubType(transAS2SubTypes, subType) + fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(value[0:2]), binary.BigEndian.Uint32(value[2:]))
}

// Transitive IPv4 Specific Extended Community
func type1(subType uint8, value []byte) string {
	return getSubType(transIPv4SubTypes, subType) + fmt.Sprintf("%s:%d", net.IP(value[0:4]).To4().String(), binary.BigEndian.Uint16(value[4:]))
}

// Transitive Four-Octet AS-Specific Extended Community
func type2(subType uint8, value []byte) string {
	return getSubType(transAS4SubTypes, subType) + fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(value[0:4]), binary.BigEndian.Uint16(value[4:]))
}

// Transitive Opaque Extended Community
func type3(subType uint8, value []byte) string {
	var s string
	switch subType {
	case 0xb:
		s = fmt.Sprintf("%d", binary.BigEndian.Uint32(value[0:4]))
	case 0xc:
		s = fmt.Sprintf("%d", binary.BigEndian.Uint16(value[2:4]))
	default:
		s = fmt.Sprintf("%d", binary.BigEndian.Uint32(value[0:4]))
	}
	return getSubType(transOpaqueSubTypes, subType) + s
}

// EVPN Extended Community
func type6(subType uint8, value []byte) string {
	var s string
	switch subType {
	case 0x01:
		l := make([]byte, 4)
		copy(l, value[3:])
		s = fmt.Sprintf("%d:%d", value[0], binary.BigEndian.Uint32(l))
	case 0x02:
		fallthrough
	case 0x03:
		for i, m := range value {
			s += tools.ConvertToHex(m)
			if i < len(value)-1 {
				s += ":"
			}
		}
	case 0x00:
		s = fmt.Sprintf("%d:%d", value[0], binary.BigEndian.Uint32(value[2:]))
	case 0x06:
		s = fmt.Sprintf("%d:0x%04x", value[0], binary.BigEndian.Uint16(value[1:]))
	default:
		s = fmt.Sprintf("%d", binary.BigEndian.Uint32(value[0:4]))
	}

	return getSubType(evpnSubTypes, subType) + s
}

// 0x08 Flow spec redirect/mirror to IP next-hop [draft-simpson-idr-flowspec-redirect] 2012-09-28
func type8(subType uint8, value []byte) string {
	return ECPFlowspec + "redirect_to_ip_next_hop"
}

// Non-Transitive Two-Octet AS-Specific Extended Community
func type40(subType uint8, value []byte) string {
	var s string
	switch subType {
	case 0x04:
		f := binary.BigEndian.Uint32(value[0:4])
		s = fmt.Sprintf("%03f", math.Float32frombits(f))
	default:
		s = fmt.Sprintf("%d", binary.BigEndian.Uint32(value[0:4]))

	}

	return getSubType(nonTransAS2SubTypes, subType) + s
}

// Flowspec Extended Community
func type80(subType uint8, value []byte) string {
	var s string

	if len(value) == 6 {
		switch subType {
		case 0x06:
			s = fmt.Sprintf("AS: %d Rate: %d bps", binary.BigEndian.Uint16(value[:2]), uint32(math.Float32frombits(binary.BigEndian.Uint32(value[2:])))*8)
		case 0x08:
			s = fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(value[0:2]), binary.BigEndian.Uint32(value[2:]))
		case 0x09:
			fallthrough
		case 0x07:
			// TODO (sbezverk) add corresponding transformation actions
			fallthrough
		default:
			s = tools.MessageHex(value)
		}
	} else {
		s = fmt.Sprintf("invalid value length of %d", len(value))
	}
	return getSubType(flowspecSubTypes, subType) + s
}

func type81(subType uint8, value []byte) string {
	var s string

	if len(value) == 6 {
		switch subType {
		case 0x08:
			s = fmt.Sprintf("%s:%d", net.IP(value[0:4]).To4().String(), binary.BigEndian.Uint16(value[4:]))
		default:
			s = tools.MessageHex(value)
		}
	} else {
		s = fmt.Sprintf("invalid value length of %d", len(value))
	}
	return getSubType(flowspecSubTypes, subType) + s
}

func type82(subType uint8, value []byte) string {
	var s string

	if len(value) == 6 {
		switch subType {
		case 0x08:
			s = fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(value[0:4]), binary.BigEndian.Uint16(value[4:]))
		default:
			s = tools.MessageHex(value)
		}
	} else {
		s = fmt.Sprintf("invalid value length of %d", len(value))
	}
	return getSubType(flowspecSubTypes, subType) + s
}

// extComm defines a map with Extended Community as a key, it return a function to process a type specific sub type.
var extComm = map[uint8]func(uint8, []byte) string{
	0x0:  type0,
	0x1:  type1,
	0x2:  type2,
	0x3:  type3,
	0x6:  type6,
	0x8:  type8,
	0x40: type40,
	0x80: type80,
	0x81: type81,
	0x82: type82,
}

func (ext *ExtCommunity) String() string {
	var s string
	// var prefix string
	var subType uint8
	if ext.SubType == nil {
		subType = 0xff
	} else {
		subType = *ext.SubType
	}
	f := extComm[ext.Type]
	if f == nil {
		s = "unknown="
		s += fmt.Sprintf("Type: %d Subtype: %d Value: %s", ext.Type, subType, tools.MessageHex(ext.Value))
		return s
	}
	return f(subType, ext.Value)
}
