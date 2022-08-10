package bgpls

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/tools"
)

// NLRI defines BGP-LS NLRI object as collection of BGP-LS TLVs
// https://tools.ietf.org/html/rfc7752#section-3.3
type NLRI struct {
	LS []TLV
}

// GetLinkID returns Local and Remote Link ID as a slice of uint32
func (ls *NLRI) GetLinkID() ([]uint32, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 258 {
			continue
		}
		if tlv.Length < 8 {
			return nil, fmt.Errorf("not enough bytes to decode Local Remote Id TLV")
		}
		return []uint32{binary.BigEndian.Uint32(tlv.Value[:4]), binary.BigEndian.Uint32(tlv.Value[4:])}, nil
	}

	return nil, fmt.Errorf("tlv 258 not found")
}

// GetMTID returns string of MT-ID TLV containing the array of MT-IDs of all
// topologies where the node is reachable is allowed
func (ls *NLRI) GetMTID() []*base.MultiTopologyIdentifier {
	for _, tlv := range ls.LS {
		if tlv.Type != 263 {
			continue
		}
		if len(tlv.Value) == 0 {
			return nil
		}
		mtid, err := base.UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
		if err != nil {
			return nil
		}
		return mtid
	}

	return nil
}

// GetAllAttribute returns a slice with all attribute types found in BGP-LS NLRI object
func (ls *NLRI) GetAllAttribute() []uint16 {
	attrs := make([]uint16, 0)
	for _, attr := range ls.LS {
		attrs = append(attrs, attr.Type)
	}

	return attrs
}

// GetNodeFlags reeturns Flag Bits TLV carries a bit mask describing node attributes.
func (ls *NLRI) GetNodeFlags() (*NodeAttrFlags, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 1024 {
			continue
		}
		return UnmarshalNodeAttrFlags(tlv.Value)
	}
	return nil, fmt.Errorf("node found")
}

// GetNodeName returns Value field identifies the symbolic name of the router node
func (ls *NLRI) GetNodeName() string {
	for _, tlv := range ls.LS {
		if tlv.Type != 1026 {
			continue
		}
		return string(tlv.Value)
	}
	return ""
}

// GetISISAreaID returns a string IS-IS Area Identifier TLVs
func (ls *NLRI) GetISISAreaID() string {
	var s string
	for _, tlv := range ls.LS {
		if tlv.Type != 1027 {
			continue
		}
		for p := 0; p < len(tlv.Value); {
			s += fmt.Sprintf("%02x", tlv.Value[p])
			p++
			if p >= len(tlv.Value) {
				break
			}
			s += "."
			s += fmt.Sprintf("%02x", tlv.Value[p])
			p++
			if p >= len(tlv.Value) {
				break
			}
			s += fmt.Sprintf("%02x", tlv.Value[p])
			p++
			if p >= len(tlv.Value) {
				break
			}
			if p < len(tlv.Value) {
				s += ","
			}
		}
	}

	return s
}

// GetLocalIPv4RouterID returns string with local Node IPv4 router ID
func (ls *NLRI) GetLocalIPv4RouterID() string {
	for _, tlv := range ls.LS {
		if tlv.Type != 1028 {
			continue
		}
		return net.IP(tlv.Value).To4().String()
	}

	return ""
}

// GetLocalIPv6RouterID returns string with local Node IPv6 router ID
func (ls *NLRI) GetLocalIPv6RouterID() string {
	for _, tlv := range ls.LS {
		if tlv.Type != 1029 {
			continue
		}
		return net.IP(tlv.Value).To16().String()
	}

	return ""
}

// GetRemoteIPv4RouterID returns string with remote Node IPv4 router ID
func (ls *NLRI) GetRemoteIPv4RouterID() string {
	for _, tlv := range ls.LS {
		if tlv.Type != 1030 {
			continue
		}
		return net.IP(tlv.Value).To4().String()
	}

	return ""
}

// GetRemoteIPv6RouterID returns string with remote Node IPv6 router ID
func (ls *NLRI) GetRemoteIPv6RouterID() string {
	for _, tlv := range ls.LS {
		if tlv.Type != 1031 {
			continue
		}
		return net.IP(tlv.Value).To16().String()
	}

	return ""
}

// GetNodeMSD returns Node's MSD object
func (ls *NLRI) GetNodeMSD() ([]*base.MSDTV, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 266 {
			continue
		}
		return base.UnmarshalMSDTV(tlv.Value)
	}

	return nil, fmt.Errorf("not found")
}

// GetLinkMSD returns Link's MSD object
func (ls *NLRI) GetLinkMSD() ([]*base.MSDTV, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 267 {
			continue
		}
		return base.UnmarshalMSDTV(tlv.Value)
	}

	return nil, fmt.Errorf("not found")
}

// GetNodeSRCapabilities returns string representation of SR Capabilities
func (ls *NLRI) GetNodeSRCapabilities(proto base.ProtoID) (*sr.Capability, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 1034 {
			continue
		}
		return sr.UnmarshalSRCapability(tlv.Value, proto)
	}

	return nil, fmt.Errorf("not found")
}

// GetSRAlgorithm returns a list of SR Algorithms
func (ls *NLRI) GetSRAlgorithm() []int {
	a := make([]int, 0)
	for _, tlv := range ls.LS {
		if tlv.Type != 1035 {
			continue
		}
		for p := 0; p < len(tlv.Value); p++ {
			a = append(a, int(tlv.Value[p]))
		}
		break
	}

	return a
}

// GetNodeSRLocalBlock returns SR LocalBlock object
func (ls *NLRI) GetNodeSRLocalBlock() *sr.LocalBlock {
	for _, tlv := range ls.LS {
		if tlv.Type != 1036 {
			continue
		}
		lb, err := sr.UnmarshalSRLocalBlock(tlv.Value)
		if err != nil {
			return nil
		}
		return lb
	}

	return nil
}

// GetFlexAlgoDefinition returns node's FlexAlgo Definition object
func (ls *NLRI) GetFlexAlgoDefinition() ([]*FlexAlgoDefinition, error) {
	fads := make([]*FlexAlgoDefinition, 0)
	for _, tlv := range ls.LS {
		if tlv.Type != 1039 {
			continue
		}
		fad, err := UnmarshalFlexAlgoDefinition(tlv.Value)
		if err != nil {
			return nil, err
		}
		fads = append(fads, fad)
	}

	return fads, nil
}

// GetFlexAlgoPrefixMetric returns prefix's FlexAlgo Metric object
func (ls *NLRI) GetFlexAlgoPrefixMetric() ([]*FlexAlgoPrefixMetric, error) {
	faps := make([]*FlexAlgoPrefixMetric, 0)
	for _, tlv := range ls.LS {
		if tlv.Type != 1044 {
			continue
		}
		fap, err := UnmarshalFlexAlgoPrefixMetric(tlv.Value)
		if err != nil {
			return nil, err
		}
		faps = append(faps, fap)
	}

	return faps, nil
}

// GetLSPrefixSID returns a slice of  Prefix SID TLV objects
func (ls *NLRI) GetLSPrefixSID(proto base.ProtoID) ([]*sr.PrefixSIDTLV, error) {
	ps := make([]*sr.PrefixSIDTLV, 0)
	for _, tlv := range ls.LS {
		if tlv.Type != 1158 {
			continue
		}
		p, err := sr.UnmarshalPrefixSIDTLV(tlv.Value, proto)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p)
	}

	return ps, nil
}

// GetLSSRv6Locator returns a slice of SRv6 locator objects
func (ls *NLRI) GetLSSRv6Locator() (*srv6.LocatorTLV, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 1162 {
			continue
		}
		return srv6.UnmarshalSRv6LocatorTLV(tlv.Value)
	}

	return nil, fmt.Errorf("not found")
}

// GetLSPrefixAttrFlags returns a Prefix Attribute Flags interface
func (ls *NLRI) GetLSPrefixAttrFlags(proto base.ProtoID) (PrefixAttrFlags, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 1170 {
			continue
		}
		return UnmarshalPrefixAttrFlags(tlv.Value, proto)
	}

	return nil, fmt.Errorf("not found")
}

// GetLSSourceRouterID returns a Prefix Source Router ID
func (ls *NLRI) GetLSSourceRouterID() (string, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 1171 {
			continue
		}
		switch len(tlv.Value) {
		case 4:
			return net.IP(tlv.Value).To4().String(), nil
		case 16:
			return net.IP(tlv.Value).To16().String(), nil
		default:
			return "", fmt.Errorf("invalid length %d of Source Router ID TLV", len(tlv.Value))
		}
	}

	return "", fmt.Errorf("not found")
}

// GetLSSRv6ENDXSID returns SRv6 END.X SID TLV
func (ls *NLRI) GetLSSRv6ENDXSID() ([]*srv6.EndXSIDTLV, error) {
	endxs := make([]*srv6.EndXSIDTLV, 0)
	for _, tlv := range ls.LS {
		if tlv.Type != 1106 {
			continue
		}
		endx, err := srv6.UnmarshalSRv6EndXSIDTLV(tlv.Value)
		if err != nil {
			return nil, err
		}
		endxs = append(endxs, endx)
	}
	return endxs, nil
}

// GetNodeSRv6CapabilitiesTLV returns string representation of SRv6 Capabilities TLV
func (ls *NLRI) GetNodeSRv6CapabilitiesTLV() (*srv6.CapabilityTLV, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 1038 {
			continue
		}
		return srv6.UnmarshalSRv6CapabilityTLV(tlv.Value)
	}
	return nil, fmt.Errorf("not found")
}

// GetAdminGroup returns Administrative group (color)
func (ls *NLRI) GetAdminGroup() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1088 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}

	return 0
}

// GetTEDefaultMetric returns value of TE Default Metric
func (ls *NLRI) GetTEDefaultMetric() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1092 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}

	return 0
}

// GetIGPMetric returns IGP Metric
func (ls *NLRI) GetIGPMetric() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1095 {
			continue
		}
		m := make([]byte, 4)
		// 1095 TLV has varaible length
		// 1, 2 or 3 bytes, depending on the length copying the actual value into the right position.
		copy(m[4-tlv.Length:], tlv.Value)
		return binary.BigEndian.Uint32(m)
	}

	return 0
}

// GetPrefixMetric returns  Prefix Metric
func (ls *NLRI) GetPrefixMetric() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1155 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}

	return 0
}

// GetMaxLinkBandwidth returns value of Maximum Link Bandwidth in bps
func (ls *NLRI) GetMaxLinkBandwidth() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1089 {
			continue
		}
		return uint32(math.Float32frombits(binary.BigEndian.Uint32(tlv.Value))) * 8
	}

	return 0
}

// GetMaxReservableLinkBandwidth returns value of Maximum Reservable Link Bandwidth in bps
func (ls *NLRI) GetMaxReservableLinkBandwidth() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1090 {
			continue
		}
		return uint32(math.Float32frombits(binary.BigEndian.Uint32(tlv.Value))) * 8
	}

	return 0
}

// GetUnreservedLinkBandwidth returns eight 32-bit number in bps
func (ls *NLRI) GetUnreservedLinkBandwidth() []uint32 {
	unResrved := make([]uint32, 8)
	for _, tlv := range ls.LS {
		if tlv.Type != 1091 {
			continue
		}
		for p := 0; p < len(tlv.Value); {
			unResrved = append(unResrved, uint32(math.Float32frombits(binary.BigEndian.Uint32(tlv.Value[p:p+4])))*8)
			p += 4
		}
		return unResrved
	}

	return nil
}

// GetLinkProtectionType returns value of Link Protection Type
func (ls *NLRI) GetLinkProtectionType() uint16 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1093 {
			continue
		}
		return binary.BigEndian.Uint16(tlv.Value)
	}

	return 0
}

// GetLinkMPLSProtocolMask returns value of MPLS Protocol Mask
func (ls *NLRI) GetLinkMPLSProtocolMask() uint8 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1094 {
			continue
		}
		return uint8(tlv.Value[0])
	}

	return 0
}

// GetSRLG returns slice of uint32 carrying data structure
// consisting of a (variable) list of SRLG values
func (ls *NLRI) GetSRLG() []uint32 {
	srlg := make([]uint32, 0)
	for _, tlv := range ls.LS {
		if tlv.Type != 1096 {
			continue
		}
		for p := 0; p < len(tlv.Value); {
			srlg = append(srlg, binary.BigEndian.Uint32(tlv.Value[p:p+4]))
			p += 4
		}
		return srlg
	}

	return nil
}

// GetLinkName returns Link's name
func (ls *NLRI) GetLinkName() string {
	for _, tlv := range ls.LS {
		if tlv.Type != 1098 {
			continue
		}
		return string(tlv.Value)
	}

	return ""
}

// GetPeerNodeSID returns PeerNode SID TLV includes a SID associated with the BGP peer node
// that is described by a BGP-LS Link NLRI
func (ls *NLRI) GetPeerNodeSID() (*sr.PeerSID, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 1101 {
			continue
		}
		return sr.UnmarshalPeerSID(tlv.Value)
	}

	return nil, fmt.Errorf("not found")
}

// GetPeerAdjSID returns PeerAdj SID TLV includes a SID associated with the BGP peer node
// that is described by a BGP-LS Link NLRI
func (ls *NLRI) GetPeerAdjSID() (*sr.PeerSID, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 1102 {
			continue
		}
		return sr.UnmarshalPeerSID(tlv.Value)
	}

	return nil, fmt.Errorf("not found")
}

// GetPeerSetSID returns PeerSet SID TLV includes a SID associated with the BGP peer node
// that is described by a BGP-LS Link NLRI
func (ls *NLRI) GetPeerSetSID() (*sr.PeerSID, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 1103 {
			continue
		}
		return sr.UnmarshalPeerSID(tlv.Value)
	}

	return nil, fmt.Errorf("not found")
}

// GetSRv6EndpointBehavior returns SRv6 SID NLRI Endpoint behavior object
func (ls *NLRI) GetSRv6EndpointBehavior() *srv6.EndpointBehavior {
	for _, tlv := range ls.LS {
		if tlv.Type != 1250 {
			continue
		}
		ep, err := srv6.UnmarshalSRv6EndpointBehaviorTLV(tlv.Value)
		if err != nil {
			return nil
		}
		return ep
	}

	return nil
}

// GetSRv6BGPPeerNodeSID returns Peer Node SID object
func (ls *NLRI) GetSRv6BGPPeerNodeSID() *srv6.BGPPeerNodeSID {
	for _, tlv := range ls.LS {
		if tlv.Type != 1251 {
			continue
		}
		sid, err := srv6.UnmarshalSRv6BGPPeerNodeSIDTLV(tlv.Value)
		if err != nil {
			return nil
		}
		return sid
	}

	return nil
}

// GetSRv6SIDStructure returns SID Structure object
func (ls *NLRI) GetSRv6SIDStructure() *srv6.SIDStructure {
	for _, tlv := range ls.LS {
		if tlv.Type != 1252 {
			continue
		}
		sid, err := srv6.UnmarshalSRv6SIDStructureTLV(tlv.Value)
		if err != nil {
			return nil
		}
		return sid
	}

	return nil
}

// GetUnidirLinkDelay returns value of Unidirectional Link Delay
func (ls *NLRI) GetUnidirLinkDelay() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1114 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}

	return 0
}

// GetUnidirLinkDelayMinMax returns minimum and maximum delay values between two
//   directly connected IGP link-state neighbors of MUnidirectional Link Delay
func (ls *NLRI) GetUnidirLinkDelayMinMax() []uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1115 {
			continue
		}
		return []uint32{binary.BigEndian.Uint32(tlv.Value[:4]), binary.BigEndian.Uint32(tlv.Value[4:])}
	}

	return nil
}

// GetUnidirDelayVariation returns a value of the link delay variation between two
// directly connected IGP link-state neighbor
func (ls *NLRI) GetUnidirDelayVariation() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1116 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}

	return 0
}

// GetUnidirLinkLoss returns a value of the the loss (as a packet percentage) between two
// directly connected IGP link-state neighbor
func (ls *NLRI) GetUnidirLinkLoss() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1117 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}

	return 0
}

// GetUnidirResidualBandwidth returns a value of the the residual bandwidth between two
// directly connected IGP link-state neighbor
func (ls *NLRI) GetUnidirResidualBandwidth() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1118 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}

	return 0
}

// GetUnidirAvailableBandwidth returns a value of the the available bandwidth between two
// directly connected IGP link-state neighbor
func (ls *NLRI) GetUnidirAvailableBandwidth() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1119 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}

	return 0
}

// GetUnidirUtilizedBandwidth returns a value of the the utilized bandwidth between two
// directly connected IGP link-state neighbor
func (ls *NLRI) GetUnidirUtilizedBandwidth() uint32 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1120 {
			continue
		}
		return binary.BigEndian.Uint32(tlv.Value)
	}

	return 0
}

// GetAppSpecLinkAttr returns a slice of Application Specifc Link Attributes
func (ls *NLRI) GetAppSpecLinkAttr() ([]*AppSpecLinkAttr, error) {
	aslas := make([]*AppSpecLinkAttr, 0)
	// It appears Path Attributes can carry multiple entries of SR Adjacency SID
	for _, tlv := range ls.LS {
		if tlv.Type != 1122 {
			continue
		}
		asla, err := UnmarshalAppSpecLinkAttr(tlv.Value)
		if err != nil {
			return nil, err
		}
		aslas = append(aslas, asla)
	}

	return aslas, nil
}

// GetSRAdjacencySID returns SR Adjacency SID object
func (ls *NLRI) GetSRAdjacencySID(proto base.ProtoID) ([]*sr.AdjacencySIDTLV, error) {
	adjs := make([]*sr.AdjacencySIDTLV, 0)
	// It appears Path Attributes can carry multiple entries of SR Adjacency SID
	for _, tlv := range ls.LS {
		if tlv.Type != 1099 {
			continue
		}
		adj, err := sr.UnmarshalAdjacencySIDTLV(tlv.Value, proto)
		if err != nil {
			return nil, err
		}
		adjs = append(adjs, adj)
	}

	return adjs, nil
}

// UnmarshalBGPLSNLRI builds Prefix NLRI object
func UnmarshalBGPLSNLRI(b []byte) (*NLRI, error) {
	if glog.V(6) {
		glog.Infof("BGPLSNLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	bgpls := NLRI{}
	ls, err := UnmarshalBGPLSTLV(b)
	if err != nil {
		return nil, err
	}
	bgpls.LS = ls

	return &bgpls, nil
}
