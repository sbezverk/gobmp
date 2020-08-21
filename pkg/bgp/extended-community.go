package bgp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
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
	//	if ext.SubType != nil {
	if subType == 2 {
		return true
	}
	//	}

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
		glog.V(5).Infof("Extended community: %s", tools.MessageHex(b[p:p+8]))
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
// 0x10	Cisco VPN-Distinguisher	[Eric_Rosen]	2012-04-10
// 0x13	Route-Target Record	[draft-ietf-bess-service-chaining]	2016-08-29
// 0x80	Virtual-Network Identifier Extended Community	[Manju_Ramesh]	2019-06-19
var transAS2SubTypes = map[uint8]string{
	0x2:  "rt=",
	0x3:  "ro=",
	0x5:  "odi=",
	0x8:  "bdc=",
	0x9:  "sas=",
	0x0a: "l2i=",
	0x10: "cvd=",
	0x13: "rtr=",
	0x80: "vni=",
}

// Transitive IPv4-Address-Specific Extended Community Sub-Types
// 0x02	Route Target	[RFC4360]
// 0x03	Route Origin	[RFC4360]
// 0x05	OSPF Domain Identifier	[RFC4577]
// 0x07	OSPF Route ID	[RFC4577]
// 0x0a	L2VPN Identifier	[RFC6074]
// 0x0b	VRF Route Import	[RFC6514]
// 0x0c	Flow-spec Redirect to IPv4	[draft-ietf-idr-flowspec-redirect]	2016-03-22
// 0x10	Cisco VPN-Distinguisher	[Eric_Rosen]	2012-04-10
// 0x12	Inter-Area P2MP Segmented Next-Hop	[RFC7524]	2014-01-08
// 0x13	Route-Target Record	[draft-ietf-bess-service-chaining]	2016-08-29
// 0x14	VRF-Recursive-Next-Hop-Extended-Community	[Dhananjaya_Rao]	2020-08-04
// 0x20	MVPN SA RP-address Extended Community	[draft-zzhang-bess-mvpn-msdp-sa-interoperation]	2018-03-26
var transIPv4SubTypes = map[uint8]string{
	0x2:  "rt=",
	0x3:  "ro=",
	0x5:  "odi=",
	0x7:  "ori=",
	0x0a: "l2i=",
	0x0b: "vri=",
	0x0c: "fsr=",
	0x10: "cvd=",
	0x12: "snh=",
	0x13: "rtr=",
	0x14: "rnh=",
	0x20: "rpa=",
}

// Transitive Four-Octet AS-Specific Extended Community Sub-Types
// 0x02	Route Target	[RFC5668]
// 0x03	Route Origin	[RFC5668]
// 0x04	Generic (deprecated)	[draft-ietf-idr-as4octet-extcomm-generic-subtype]
// 0x05	OSPF Domain Identifier	[RFC4577]
// 0x08	BGP Data Collection	[RFC4384]
// 0x09	Source AS	[RFC6514]
// 0x10	Cisco VPN Identifier	[Eric_Rosen]	2012-04-10
// 0x13	Route-Target Record	[draft-ietf-bess-service-chaining]	2016-08-29
var transAS4SubTypes = map[uint8]string{
	0x2:  "rt=",
	0x3:  "ro=",
	0x4:  "deprecated=",
	0x5:  "odi=",
	0x8:  "bdc=",
	0x9:  "sas=",
	0x10: "cvd=",
	0x13: "rtr=",
}

// Transitive Opaque Extended Community Sub-Types
// 0x01	Cost Community	[draft-ietf-idr-custom-decision]	2014-07-15
// 0x03	CP-ORF	[RFC7543]	2014-09-24
// 0x04	Extranet Source Extended Community	[RFC7900]	2016-04-28
// 0x05	Extranet Separation Extended Community	[RFC7900]	2016-04-28
// 0x06	OSPF Route Type	[RFC4577]
// 0x07	Additional PMSI Tunnel Attribute Flags	[RFC7902]	2016-05-12
// 0x08	Context Label Space ID Extended Community	[draft-ietf-bess-mvpn-evpn-aggregation-label]	2019-01-23
// 0x0b	Color Extended Community	[RFC5512]
// 0x0c	Encapsulation Extended Community	[RFC5512]
// 0x0d	Default Gateway	[Yakov_Rekhter]	2012-07-10
// 0x0e	Point-to-Point-to-Multipoint (PPMP) Label	[Rishabh_Parekh]	2016-01-19
// 0x14	Consistent Hash Sort Order	[draft-ietf-bess-service-chaining]	2016-05-11
// 0xaa	LoadBalance	[draft-ietf-bess-service-chaining]	2017-11-01
var transOpaqueSubTypes = map[uint8]string{
	0x2:  "cost=",
	0x3:  "cporf=",
	0x4:  "esrc=",
	0x5:  "esep=",
	0x6:  "ort=",
	0x7:  "taf=",
	0x8:  "cls=",
	0xb:  "color=",
	0xc:  "encap=",
	0xe:  "dgw=",
	0x14: "chso=",
	0xaa: "lb=",
}

// EVPN Extended Community Sub-Types
// 0x00	MAC Mobility	[RFC7432]	2012-07-11
// 0x01	ESI Label	[RFC7432]	2012-07-11
// 0x02	ES-Import Route Target	[RFC7432]	2012-07-11
// 0x03	EVPN Router’s MAC Extended Community	[draft-sajassi-l2vpn-evpn-inter-subnet-forwarding]	2014-09-23
// 0x04	EVPN Layer 2 Attributes	[RFC8214]	2016-05-11
// 0x05	E-Tree Extended Community	[RFC8317]	2016-05-11
// 0x06	DF Election Extended Community	[RFC8584]	2016-05-11
// 0x07	I-SID Extended Community	[draft-sajassi-bess-evpn-virtual-eth-segment]	2016-05-11
// 0x08	ND Extended Community	[draft-snr-bess-evpn-na-flags]	2017-01-10
// 0x09	Multicast Flags Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]	2017-11-06
// 0x0A	EVI-RT Type 0 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]	2017-11-06
// 0x0B	EVI-RT Type 1 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]	2018-06-06
// 0x0C	EVI-RT Type 2 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]	2018-06-06
// 0x0D	EVI-RT Type 3 Extended Community	[draft-ietf-bess-evpn-igmp-mld-proxy]	2018-06-26
// 0x0E	EVPN Attachment Circuit Extended Community	[draft-sajassi-bess-evpn-ac-aware-bundling]	2019-01-23
// 0x0F	Service Carving Timestamp	[draft-ietf-bess-evpn-fast-df-recovery-01]	2020-05-29
var evpnSubTypes = map[uint8]string{
	0x0: "macmob=",
	0x1: "esi-l=",
	0x2: "es-irt=",
	0x3: "rmac=",
	0x4: "l2attr=",
	0x5: "e-tree=",
	0x6: "df-elect=",
	0x7: "i-sid=",
	0x8: "nd=",
	0x9: "mflag=",
	0xa: "evi-rt0=",
	0xb: "evi-rt1=",
	0xc: "evi-rt2=",
	0xd: "evi-rt3=",
	0xe: "ac=",
	0xf: "sct=",
}

// Non-Transitive Two-Octet AS-Specific Extended Community Sub-Types
// 0x04	Link Bandwidth Extended Community	[draft-ietf-idr-link-bandwidth-00]
// 0x80	Virtual-Network Identifier Extended Community	[draft-drao-bgp-l3vpn-virtual-network-overlays]	2015-09-29
var nonTransAS2SubTypes = map[uint8]string{
	0x4:  "link-bw=",
	0x80: "vni=",
}

func getSubType(m map[uint8]string, subType uint8) string {
	s := "Subtype unknown="
	var ok bool
	if s, ok = m[subType]; ok {
		return s
	}
	return s
}

//Transitive Two-Octet AS-Specific Extended Community
func type0(subType uint8, value []byte) string {
	return getSubType(transAS2SubTypes, subType) + fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(value[0:2]), binary.BigEndian.Uint32(value[2:]))
}

// Transitive IPv4 Specific Extended Community
func type1(subType uint8, value []byte) string {
	return getSubType(transIPv4SubTypes, subType) + fmt.Sprintf("%s:%d", net.IP(value[0:4]).To4().String(), binary.BigEndian.Uint16(value[4:]))
}

//Transitive Four-Octet AS-Specific Extended Community
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
		for i, m := range value {
			s += fmt.Sprintf("%02x", m)
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

// extComm defines a map with Extended Community as a key, it return a function to process a type specific sub type.
var extComm = map[uint8]func(uint8, []byte) string{
	0x0:  type0,
	0x1:  type1,
	0x2:  type2,
	0x3:  type3,
	0x6:  type6,
	0x40: type40,
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
		s += "unknown="
		s += fmt.Sprintf("Type: %d Subtype: %d Value: %s", ext.Type, subType, tools.MessageHex(ext.Value))
		return s
	}
	return f(subType, ext.Value)
}
