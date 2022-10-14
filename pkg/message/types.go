package message

import (
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/flowspec"
	"github.com/sbezverk/gobmp/pkg/prefixsid"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/gobmp/pkg/srpolicy"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

// PeerStateChange defines a message format sent to as a result of BMP Peer Up or Peer Down message
type PeerStateChange struct {
	Key             string         `json:"_key,omitempty"`
	ID              string         `json:"_id,omitempty"`
	Rev             string         `json:"_rev,omitempty"`
	Action          string         `json:"action,omitempty"` // Action can be "add" for peer up and "del" for peer down message
	Sequence        int            `json:"sequence,omitempty"`
	Hash            string         `json:"hash,omitempty"`
	RouterHash      string         `json:"router_hash,omitempty"`
	Name            string         `json:"name,omitempty"`
	RemoteBGPID     string         `json:"remote_bgp_id,omitempty"`
	RouterIP        string         `json:"router_ip,omitempty"`
	Timestamp       string         `json:"timestamp,omitempty"`
	RemoteASN       uint32         `json:"remote_asn,omitempty"`
	RemoteIP        string         `json:"remote_ip,omitempty"`
	PeerType        uint8          `json:"peer_type"`
	PeerRD          string         `json:"peer_rd,omitempty"`
	RemotePort      int            `json:"remote_port,omitempty"`
	LocalASN        uint32         `json:"local_asn,omitempty"`
	LocalIP         string         `json:"local_ip,omitempty"`
	LocalPort       int            `json:"local_port,omitempty"`
	LocalBGPID      string         `json:"local_bgp_id,omitempty"`
	InfoData        []byte         `json:"info_data,omitempty"`
	AdvCapabilities bgp.Capability `json:"adv_cap,omitempty"`
	RcvCapabilities bgp.Capability `json:"recv_cap,omitempty"`
	RemoteHolddown  int            `json:"remote_holddown,omitempty"`
	AdvHolddown     int            `json:"adv_holddown,omitempty"`
	BMPReason       int            `json:"bmp_reason,omitempty"`
	BMPErrorCode    int            `json:"bmp_error_code,omitempty"`
	BMPErrorSubCode int            `json:"bmp_error_sub_code,omitempty"`
	ErrorText       string         `json:"error_text,omitempty"`
	IsL3VPN         bool           `json:"is_l"`
	IsPrepolicy     bool           `json:"is_prepolicy"`
	IsIPv4          bool           `json:"is_ipv4"`
	TableName       string         `json:"table_name,omitempty"`
	// Values are assigned based on PerPeerHeader flas
	IsAdjRIBInPost   bool `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool `json:"is_adj_rib_out_post_policy"`
	IsLocRIBFiltered bool `json:"is_loc_rib_filtered"`
}

// UnicastPrefix defines a message format sent as a result of BMP Route Monitor message
// which carries BGP Update with original NLRI information.
type UnicastPrefix struct {
	Key            string              `json:"_key,omitempty"`
	ID             string              `json:"_id,omitempty"`
	Rev            string              `json:"_rev,omitempty"`
	Action         string              `json:"action,omitempty"` // Action can be "add" or "del"
	Sequence       int                 `json:"sequence,omitempty"`
	Hash           string              `json:"hash,omitempty"`
	RouterHash     string              `json:"router_hash,omitempty"`
	RouterIP       string              `json:"router_ip,omitempty"`
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
	PeerHash       string              `json:"peer_hash,omitempty"`
	PeerIP         string              `json:"peer_ip,omitempty"`
	PeerType       uint8               `json:"peer_type"`
	PeerASN        uint32              `json:"peer_asn,omitempty"`
	Timestamp      string              `json:"timestamp,omitempty"`
	Prefix         string              `json:"prefix,omitempty"`
	PrefixLen      int32               `json:"prefix_len,omitempty"`
	IsIPv4         bool                `json:"is_ipv4"`
	OriginAS       int32               `json:"origin_as,omitempty"`
	Nexthop        string              `json:"nexthop,omitempty"`
	IsNexthopIPv4  bool                `json:"is_nexthop_ipv4"`
	PathID         int32               `json:"path_id,omitempty"`
	Labels         []uint32            `json:"labels,omitempty"`
	PrefixSID      *prefixsid.PSid     `json:"prefix_sid,omitempty"`
	// Values are assigned based on PerPeerHeader flas
	IsAdjRIBInPost   bool `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool `json:"is_adj_rib_out_post_policy"`
	IsLocRIBFiltered bool `json:"is_loc_rib_filtered"`
}

// LSNode defines a structure of LS Node message
type LSNode struct {
	Key                 string                          `json:"_key,omitempty"`
	ID                  string                          `json:"_id,omitempty"`
	Rev                 string                          `json:"_rev,omitempty"`
	Action              string                          `json:"action,omitempty"` // Action can be "add" or "del"
	Sequence            int                             `json:"sequence,omitempty"`
	Hash                string                          `json:"hash,omitempty"`
	RouterHash          string                          `json:"router_hash,omitempty"`
	DomainID            int64                           `json:"domain_id"`
	RouterIP            string                          `json:"router_ip,omitempty"`
	PeerHash            string                          `json:"peer_hash,omitempty"`
	PeerIP              string                          `json:"peer_ip,omitempty"`
	PeerType            uint8                           `json:"peer_type"`
	PeerASN             uint32                          `json:"peer_asn,omitempty"`
	Timestamp           string                          `json:"timestamp,omitempty"`
	IGPRouterID         string                          `json:"igp_router_id,omitempty"`
	RouterID            string                          `json:"router_id,omitempty"`
	ASN                 uint32                          `json:"asn,omitempty"`
	LSID                uint32                          `json:"ls_id,omitempty"`
	MTID                []*base.MultiTopologyIdentifier `json:"mt_id_tlv,omitempty"`
	AreaID              string                          `json:"area_id"`
	Protocol            string                          `json:"protocol,omitempty"`
	ProtocolID          base.ProtoID                    `json:"protocol_id,omitempty"`
	NodeFlags           *bgpls.NodeAttrFlags            `json:"node_flags,omitempty"`
	Name                string                          `json:"name,omitempty"`
	SRCapabilities      *sr.Capability                  `json:"ls_sr_capabilities,omitempty"`
	SRAlgorithm         []int                           `json:"sr_algorithm,omitempty"`
	SRLocalBlock        *sr.LocalBlock                  `json:"sr_local_block,omitempty"`
	SRv6CapabilitiesTLV *srv6.CapabilityTLV             `json:"srv6_capabilities_tlv,omitempty"`
	NodeMSD             []*base.MSDTV                   `json:"node_msd,omitempty"`
	FlexAlgoDefinition  []*bgpls.FlexAlgoDefinition     `json:"flex_algo_definition,omitempty"`
	// Values are assigned based on PerPeerHeader flas
	IsAdjRIBInPost   bool `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool `json:"is_adj_rib_out_post_policy"`
	IsLocRIBFiltered bool `json:"is_loc_rib_filtered"`
}

// LSLink defines a structure of LS link message
type LSLink struct {
	Key                   string                        `json:"_key,omitempty"`
	ID                    string                        `json:"_id,omitempty"`
	Rev                   string                        `json:"_rev,omitempty"`
	Action                string                        `json:"action,omitempty"`
	Sequence              int                           `json:"sequence,omitempty"`
	Hash                  string                        `json:"hash,omitempty"`
	RouterHash            string                        `json:"router_hash,omitempty"`
	RouterIP              string                        `json:"router_ip,omitempty"`
	DomainID              int64                         `json:"domain_id"`
	PeerHash              string                        `json:"peer_hash,omitempty"`
	PeerIP                string                        `json:"peer_ip,omitempty"`
	PeerType              uint8                         `json:"peer_type"`
	PeerASN               uint32                        `json:"peer_asn,omitempty"`
	Timestamp             string                        `json:"timestamp,omitempty"`
	IGPRouterID           string                        `json:"igp_router_id,omitempty"`
	RouterID              string                        `json:"router_id,omitempty"`
	LSID                  uint32                        `json:"ls_id,omitempty"`
	Protocol              string                        `json:"protocol,omitempty"`
	ProtocolID            base.ProtoID                  `json:"protocol_id,omitempty"`
	AreaID                string                        `json:"area_id"`
	Nexthop               string                        `json:"nexthop,omitempty"`
	MTID                  *base.MultiTopologyIdentifier `json:"mt_id_tlv,omitempty"`
	LocalLinkID           uint32                        `json:"local_link_id,omitempty"`
	RemoteLinkID          uint32                        `json:"remote_link_id,omitempty"`
	LocalLinkIP           string                        `json:"local_link_ip,omitempty"`
	RemoteLinkIP          string                        `json:"remote_link_ip,omitempty"`
	IGPMetric             uint32                        `json:"igp_metric,omitempty"`
	AdminGroup            uint32                        `json:"admin_group,omitempty"`
	MaxLinkBW             uint32                        `json:"max_link_bw,omitempty"`
	MaxResvBW             uint32                        `json:"max_resv_bw,omitempty"`
	UnResvBW              []uint32                      `json:"unresv_bw,omitempty"`
	TEDefaultMetric       uint32                        `json:"te_default_metric,omitempty"`
	LinkProtection        uint16                        `json:"link_protection,omitempty"`
	MPLSProtoMask         uint8                         `json:"mpls_proto_mask,omitempty"`
	SRLG                  []uint32                      `json:"srlg,omitempty"`
	LinkName              string                        `json:"link_name,omitempty"`
	RemoteNodeHash        string                        `json:"remote_node_hash,omitempty"`
	LocalNodeHash         string                        `json:"local_node_hash,omitempty"`
	RemoteIGPRouterID     string                        `json:"remote_igp_router_id,omitempty"`
	RemoteRouterID        string                        `json:"remote_router_id,omitempty"`
	LocalNodeASN          uint32                        `json:"local_node_asn,omitempty"`
	RemoteNodeASN         uint32                        `json:"remote_node_asn,omitempty"`
	BGPRouterID           string                        `json:"bgp_router_id,omitempty"`        // Local Node Descriptor's TLV 516
	BGPRemoteRouterID     string                        `json:"bgp_remote_router_id,omitempty"` // Remote Node Descriptor's TLV 516
	MemberAS              uint32                        `json:"member_as,omitempty"`            // Node Descriptor's TLV 517
	PeerNodeSID           *sr.PeerSID                   `json:"peer_node_sid,omitempty"`
	PeerAdjSID            *sr.PeerSID                   `json:"peer_adj_sid,omitempty"`
	PeerSetSID            *sr.PeerSID                   `json:"peer_set_sid,omitempty"`
	SRv6BGPPeerNodeSID    *srv6.BGPPeerNodeSID          `json:"srv6_bgp_peer_node_sid,omitempty"`
	SRv6ENDXSID           []*srv6.EndXSIDTLV            `json:"srv6_endx_sid,omitempty"`
	LSAdjacencySID        []*sr.AdjacencySIDTLV         `json:"ls_adjacency_sid,omitempty"`
	LinkMSD               []*base.MSDTV                 `json:"link_msd,omitempty"`
	AppSpecLinkAttr       []*bgpls.AppSpecLinkAttr      `json:"app_spec_link_attr,omitempty"`
	UnidirLinkDelay       uint32                        `json:"unidir_link_delay,omitempty"`
	UnidirLinkDelayMinMax []uint32                      `json:"unidir_link_delay_min_max,omitempty"`
	UnidirDelayVariation  uint32                        `json:"unidir_delay_variation,omitempty"`
	UnidirPacketLoss      uint32                        `json:"unidir_packet_loss,omitempty"`
	UnidirResidualBW      uint32                        `json:"unidir_residual_bw,omitempty"`
	UnidirAvailableBW     uint32                        `json:"unidir_available_bw,omitempty"`
	UnidirBWUtilization   uint32                        `json:"unidir_bw_utilization,omitempty"`
	// Values are assigned based on PerPeerHeader flas
	IsAdjRIBInPost   bool `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool `json:"is_adj_rib_out_post_policy"`
	IsLocRIBFiltered bool `json:"is_loc_rib_filtered"`
}

// L3VPNPrefix defines the structure of Layer 3 VPN message
type L3VPNPrefix struct {
	Key            string              `json:"_key,omitempty"`
	ID             string              `json:"_id,omitempty"`
	Rev            string              `json:"_rev,omitempty"`
	Action         string              `json:"action,omitempty"` // Action can be "add" or "del"
	Sequence       int                 `json:"sequence,omitempty"`
	Hash           string              `json:"hash,omitempty"`
	RouterHash     string              `json:"router_hash,omitempty"`
	RouterIP       string              `json:"router_ip,omitempty"`
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
	PeerHash       string              `json:"peer_hash,omitempty"`
	PeerIP         string              `json:"peer_ip,omitempty"`
	PeerType       uint8               `json:"peer_type"`
	PeerASN        uint32              `json:"peer_asn,omitempty"`
	Timestamp      string              `json:"timestamp,omitempty"`
	Prefix         string              `json:"prefix,omitempty"`
	PrefixLen      int32               `json:"prefix_len,omitempty"`
	IsIPv4         bool                `json:"is_ipv4"`
	OriginAS       int32               `json:"origin_as,omitempty"`
	Nexthop        string              `json:"nexthop,omitempty"`
	ClusterList    string              `json:"cluster_list,omitempty"`
	IsNexthopIPv4  bool                `json:"is_nexthop_ipv4"`
	PathID         int32               `json:"path_id,omitempty"`
	Labels         []uint32            `json:"labels,omitempty"`
	VPNRD          string              `json:"vpn_rd,omitempty"`
	VPNRDType      uint16              `json:"vpn_rd_type"`
	PrefixSID      *prefixsid.PSid     `json:"prefix_sid,omitempty"`
	// Values are assigned based on PerPeerHeader flas
	IsAdjRIBInPost   bool `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool `json:"is_adj_rib_out_post_policy"`
	IsLocRIBFiltered bool `json:"is_loc_rib_filtered"`
}

// LSPrefix defines a structure of LS Prefix message
type LSPrefix struct {
	Key                  string                        `json:"_key,omitempty"`
	ID                   string                        `json:"_id,omitempty"`
	Rev                  string                        `json:"_rev,omitempty"`
	Action               string                        `json:"action,omitempty"`
	Sequence             int                           `json:"sequence,omitempty"`
	Hash                 string                        `json:"hash,omitempty"`
	RouterHash           string                        `json:"router_hash,omitempty"`
	RouterIP             string                        `json:"router_ip,omitempty"`
	DomainID             int64                         `json:"domain_id"`
	PeerHash             string                        `json:"peer_hash,omitempty"`
	PeerIP               string                        `json:"peer_ip,omitempty"`
	PeerType             uint8                         `json:"peer_type"`
	PeerASN              uint32                        `json:"peer_asn,omitempty"`
	Timestamp            string                        `json:"timestamp,omitempty"`
	IGPRouterID          string                        `json:"igp_router_id,omitempty"`
	RouterID             string                        `json:"router_id,omitempty"`
	LSID                 uint32                        `json:"ls_id,omitempty"`
	ProtocolID           base.ProtoID                  `json:"protocol_id,omitempty"`
	Protocol             string                        `json:"protocol,omitempty"`
	AreaID               string                        `json:"area_id"`
	Nexthop              string                        `json:"nexthop,omitempty"`
	LocalNodeHash        string                        `json:"local_node_hash,omitempty"`
	MTID                 *base.MultiTopologyIdentifier `json:"mt_id_tlv,omitempty"`
	OSPFRouteType        uint8                         `json:"ospf_route_type,omitempty"`
	IGPFlags             *bgpls.IGPFlags               `json:"igp_flags,omitempty"`
	IGPRouteTag          []uint32                      `json:"route_tag,omitempty"`
	IGPExtRouteTag       []uint64                      `json:"ext_route_tag,omitempty"`
	OSPFFwdAddr          string                        `json:"ospf_fwd_addr,omitempty"`
	Prefix               string                        `json:"prefix,omitempty"`
	PrefixLen            int32                         `json:"prefix_len,omitempty"`
	PrefixMetric         uint32                        `json:"prefix_metric,omitempty"`
	PrefixAttrTLVs       *bgpls.PrefixAttrTLVs         `json:"prefix_attr_tlvs,omitempty"`
	FlexAlgoPrefixMetric []*bgpls.FlexAlgoPrefixMetric `json:"flex_algo_prefix_metric,omitempty"`
	SRv6Locator          *srv6.LocatorTLV              `json:"srv6_locator,omitempty"`
	// Values are assigned based on PerPeerHeader flas
	IsAdjRIBInPost   bool `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool `json:"is_adj_rib_out_post_policy"`
	IsLocRIBFiltered bool `json:"is_loc_rib_filtered"`
}

// LSSRv6SID defines a structure of LS SRv6 SID message
type LSSRv6SID struct {
	Key                  string                        `json:"_key,omitempty"`
	ID                   string                        `json:"_id,omitempty"`
	Rev                  string                        `json:"_rev,omitempty"`
	Action               string                        `json:"action,omitempty"`
	Sequence             int                           `json:"sequence,omitempty"`
	Hash                 string                        `json:"hash,omitempty"`
	RouterHash           string                        `json:"router_hash,omitempty"`
	RouterIP             string                        `json:"router_ip,omitempty"`
	DomainID             int64                         `json:"domain_id"`
	PeerHash             string                        `json:"peer_hash,omitempty"`
	PeerIP               string                        `json:"peer_ip,omitempty"`
	PeerType             uint8                         `json:"peer_type"`
	PeerASN              uint32                        `json:"peer_asn,omitempty"`
	Timestamp            string                        `json:"timestamp,omitempty"`
	IGPRouterID          string                        `json:"igp_router_id,omitempty"`
	LocalNodeASN         uint32                        `json:"local_node_asn,omitempty"`
	RouterID             string                        `json:"router_id,omitempty"`
	LSID                 uint32                        `json:"ls_id,omitempty"`
	AreaID               string                        `json:"area_id,omitempty"`
	ProtocolID           base.ProtoID                  `json:"protocol_id,omitempty"`
	Protocol             string                        `json:"protocol,omitempty"`
	Nexthop              string                        `json:"nexthop,omitempty"`
	LocalNodeHash        string                        `json:"local_node_hash,omitempty"`
	MTID                 *base.MultiTopologyIdentifier `json:"mt_id_tlv,omitempty"`
	IGPFlags             uint8                         `json:"igp_flags"`
	IGPRouteTag          uint8                         `json:"route_tag,omitempty"`
	IGPExtRouteTag       uint8                         `json:"ext_route_tag,omitempty"`
	OSPFFwdAddr          string                        `json:"ospf_fwd_addr,omitempty"`
	IGPMetric            uint32                        `json:"igp_metric,omitempty"`
	Prefix               string                        `json:"prefix,omitempty"`
	PrefixLen            int32                         `json:"prefix_len,omitempty"`
	SRv6SID              string                        `json:"srv6_sid,omitempty"`
	SRv6EndpointBehavior *srv6.EndpointBehavior        `json:"srv6_endpoint_behavior,omitempty"`
	SRv6BGPPeerNodeSID   *srv6.BGPPeerNodeSID          `json:"srv6_bgp_peer_node_sid,omitempty"`
	SRv6SIDStructure     *srv6.SIDStructure            `json:"srv6_sid_structure,omitempty"`
	// Values are assigned based on PerPeerHeader flas
	IsAdjRIBInPost   bool `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool `json:"is_adj_rib_out_post_policy"`
	IsLocRIBFiltered bool `json:"is_loc_rib_filtered"`
}

// EVPNPrefix defines the structure of EVPN message
type EVPNPrefix struct {
	Key            string              `json:"_key,omitempty"`
	ID             string              `json:"_id,omitempty"`
	Rev            string              `json:"_rev,omitempty"`
	Action         string              `json:"action,omitempty"` // Action can be "add" or "del"
	Sequence       int                 `json:"sequence,omitempty"`
	Hash           string              `json:"hash,omitempty"`
	RouterHash     string              `json:"router_hash,omitempty"`
	RouterIP       string              `json:"router_ip,omitempty"`
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
	PeerHash       string              `json:"peer_hash,omitempty"`
	RemoteBGPID    string              `json:"remote_bgp_id,omitempty"`
	PeerIP         string              `json:"peer_ip,omitempty"`
	PeerType       uint8               `json:"peer_type"`
	PeerASN        uint32              `json:"peer_asn,omitempty"`
	Timestamp      string              `json:"timestamp,omitempty"`
	IsIPv4         bool                `json:"is_ipv4"`
	OriginAS       int32               `json:"origin_as,omitempty"`
	Nexthop        string              `json:"nexthop,omitempty"`
	ClusterList    string              `json:"cluster_list,omitempty"`
	IsNexthopIPv4  bool                `json:"is_nexthop_ipv4"`
	PathID         int32               `json:"path_id,omitempty"`
	Labels         []uint32            `json:"labels,omitempty"`
	RawLabels      []uint32            `json:"rawlabels,omitempty"`
	VPNRD          string              `json:"vpn_rd,omitempty"`
	VPNRDType      uint16              `json:"vpn_rd_type"`
	ESI            string              `json:"eth_segment_id,omitempty"`
	EthTag         []byte              `json:"eth_tag,omitempty"`
	IPAddress      string              `json:"ip_address,omitempty"`
	IPLength       uint8               `json:"ip_len,omitempty"`
	GWAddress      string              `json:"gw_address,omitempty"`
	MAC            string              `json:"mac,omitempty"`
	MACLength      uint8               `json:"mac_len,omitempty"`
	RouteType      uint8               `json:"route_type,omitempty"`
	// TODO Type 3 carries nlri 22
	// https://tools.ietf.org/html/rfc6514
	// Add to the message
	// Values are assigned based on PerPeerHeader flas
	IsAdjRIBInPost   bool `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool `json:"is_adj_rib_out_post_policy"`
	IsLocRIBFiltered bool `json:"is_loc_rib_filtered"`
}

// SRPolicy defines the structure of SR Policy message
type SRPolicy struct {
	Key            string                  `json:"_key,omitempty"`
	ID             string                  `json:"_id,omitempty"`
	Rev            string                  `json:"_rev,omitempty"`
	Action         string                  `json:"action,omitempty"` // Action can be "add" or "del"
	Sequence       int                     `json:"sequence,omitempty"`
	Hash           string                  `json:"hash,omitempty"`
	RouterHash     string                  `json:"router_hash,omitempty"`
	RouterIP       string                  `json:"router_ip,omitempty"`
	BaseAttributes *bgp.BaseAttributes     `json:"base_attrs,omitempty"`
	PeerHash       string                  `json:"peer_hash,omitempty"`
	PeerIP         string                  `json:"peer_ip,omitempty"`
	PeerType       uint8                   `json:"peer_type"`
	PeerASN        uint32                  `json:"peer_asn,omitempty"`
	Timestamp      string                  `json:"timestamp,omitempty"`
	IsIPv4         bool                    `json:"is_ipv4"`
	OriginAS       int32                   `json:"origin_as,omitempty"`
	Nexthop        string                  `json:"nexthop,omitempty"`
	ClusterList    string                  `json:"cluster_list,omitempty"`
	IsNexthopIPv4  bool                    `json:"is_nexthop_ipv4"`
	PathID         int32                   `json:"path_id,omitempty"`
	Labels         []uint32                `json:"labels,omitempty"`
	Distinguisher  uint32                  `json:"distinguisher,omitempty"`
	Color          uint32                  `json:"color,omitempty"`
	Endpoint       []byte                  `json:"endpoint,omitempty"`
	PolicyName     string                  `json:"policy_name,omitempty"`
	BSID           *srpolicy.BindingSID    `json:"binding_sid,omitempty"`
	Preference     *srpolicy.Preference    `json:"preference_subtlv,omitempty"`
	Priority       byte                    `json:"priority_subtlv,omitempty"`
	PolicyPathName string                  `json:"policy_path_name,omitempty"`
	ENLP           *srpolicy.ENLP          `json:"enlp_subtlv,omitempty"`
	SegmentList    []*srpolicy.SegmentList `json:"segment_list_subtlv,omitempty"`
	// Values are assigned based on PerPeerHeader flas
	IsAdjRIBInPost   bool `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool `json:"is_adj_rib_out_post_policy"`
	IsLocRIBFiltered bool `json:"is_loc_rib_filtered"`
}

// Flowspec defines the structure of SR Policy message
type Flowspec struct {
	Key            string              `json:"_key,omitempty"`
	ID             string              `json:"_id,omitempty"`
	Rev            string              `json:"_rev,omitempty"`
	Action         string              `json:"action,omitempty"` // Action can be "add" or "del"
	Sequence       int                 `json:"sequence,omitempty"`
	RouterIP       string              `json:"router_ip,omitempty"`
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
	PeerIP         string              `json:"peer_ip,omitempty"`
	PeerType       uint8               `json:"peer_type"`
	PeerASN        uint32              `json:"peer_asn,omitempty"`
	Timestamp      string              `json:"timestamp,omitempty"`
	IsIPv4         bool                `json:"is_ipv4"`
	OriginAS       int32               `json:"origin_as,omitempty"`
	Nexthop        string              `json:"nexthop,omitempty"`
	IsNexthopIPv4  bool                `json:"is_nexthop_ipv4"`
	PathID         int32               `json:"path_id,omitempty"`
	SpecHash       string              `json:"spec_hash,omitempty"`
	Spec           []flowspec.Spec     `json:"spec,omitempty"`
	// Values are assigned based on PerPeerHeader flas
	IsAdjRIBInPost   bool `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool `json:"is_adj_rib_out_post_policy"`
	IsLocRIBFiltered bool `json:"is_loc_rib_filtered"`
}

// Stats defines a message format sent to as a result of BMP Stats Message
type Stats struct {
	Key                        string `json:"_key,omitempty"`
	ID                         string `json:"_id,omitempty"`
	Rev                        string `json:"_rev,omitempty"`
	Sequence                   int    `json:"sequence,omitempty"`
	RouterHash                 string `json:"router_hash,omitempty"`
	RouterIP                   string `json:"router_ip,omitempty"`
	PeerType                   uint8  `json:"peer_type"`
	RemoteBGPID                string `json:"remote_bgp_id,omitempty"`
	RemoteASN                  uint32 `json:"remote_asn,omitempty"`
	RemoteIP                   string `json:"remote_ip,omitempty"`
	PeerRD                     string `json:"peer_rd,omitempty"`
	Timestamp                  string `json:"timestamp,omitempty"`
	DuplicatePrefixs           uint32 `json:"duplicate_prefix,omitempty"`
	DuplicateWithDraws         uint32 `json:"duplicate_withdraws,omitempty"`
	InvalidatedDueCluster      uint32 `json:"invalidated_due_cluster,omitempty"`
	InvalidatedDueAspath       uint32 `json:"invalidated_due_aspath,omitempty"`
	InvalidatedDueOriginatorId uint32 `json:"invalidated_due_originator_id,omitempty"`
	InvalidatedAsConfed        uint32 `json:"invalidated_due_asconfed,omitempty"`
	AdjRIBsIn                  uint64 `json:"ads_rib_in,omitempty"`
	LocalRib                   uint64 `json:"local_rib,omitempty"`
	UpdatesAsWithdraw          uint32 `json:"updates_as_withdraw,omitempty"`
	PrefixesAsWithdraw         uint32 `json:"prefixes_as_withdraw,omitempty"`
}
