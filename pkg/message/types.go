package message

import "github.com/sbezverk/gobmp/pkg/srv6"

// PeerStateChange defines a message format sent to as a result of BMP Peer Up or Peer Down message
type PeerStateChange struct {
	Action           string `json:"action"` // Action can be "up" or "down"
	Sequence         int    `json:"sequence,omitempty"`
	Hash             string `json:"hash,omitempty"`
	RouterHash       string `json:"router_hash,omitempty"`
	Name             string `json:"name,omitempty"`
	RemoteBGPID      string `json:"remote_bgp_id,omitempty"`
	RouterIP         string `json:"router_ip,omitempty"`
	Timestamp        string `json:"timestamp,omitempty"`
	RemoteASN        int32  `json:"remote_asn,omitempty"`
	RemoteIP         string `json:"remote_ip,omitempty"`
	PeerRD           string `json:"peer_rd,omitempty"`
	RemotePort       int    `json:"remote_port,omitempty"`
	LocalASN         int32  `json:"local_asn,omitempty"`
	LocalIP          string `json:"local_ip,omitempty"`
	LocalPort        int    `json:"local_port,omitempty"`
	LocalBGPID       string `json:"local_bgp_id,omitempty"`
	InfoData         string `json:"info_data,omitempty"`
	AdvCapabilities  string `json:"adv_cap,omitempty"`
	RcvCapabilities  string `json:"recv_cap,omitempty"`
	RemoteHolddown   int    `json:"remote_holddown,omitempty"`
	AdvHolddown      int    `json:"adv_holddown,omitempty"`
	BMPReason        int    `json:"bmp_reason,omitempty"`
	BMPErrorCode     int    `json:"bmp_error_code,omitempty"`
	BMPErrorSubCode  int    `json:"bmp_error_sub_code,omitempty"`
	ErrorText        string `json:"error_text,omitempty"`
	IsL3VPN          bool   `json:"is_l,omitempty"`
	IsPrepolicy      bool   `json:"isprepolicy,omitempty"`
	IsIPv4           bool   `json:"is_ipv4,omitempty"`
	IsLocRIB         bool   `json:"is_locrib,omitempty"`
	IsLocRIBFiltered bool   `json:"is_locrib_filtered,omitempty"`
	TableName        string `json:"table_name,omitempty"`
}

// UnicastPrefix defines a message format sent as a result of BMP Route Monitor message
// which carries BGP Update with original NLRI information.
type UnicastPrefix struct {
	Action           string `json:"action"` // Action can be "add" or "del"
	Sequence         int    `json:"sequence,omitempty"`
	Hash             string `json:"hash,omitempty"`
	RouterHash       string `json:"router_hash,omitempty"`
	RouterIP         string `json:"router_ip,omitempty"`
	BaseAttrHash     string `json:"base_attr_hash,omitempty"`
	PeerHash         string `json:"peer_hash,omitempty"`
	PeerIP           string `json:"peer_ip,omitempty"`
	PeerASN          int32  `json:"peer_asn,omitempty"`
	Timestamp        string `json:"timestamp,omitempty"`
	Prefix           string `json:"prefix,omitempty"`
	PrefixLen        int32  `json:"prefix_len,omitempty"`
	IsIPv4           bool   `json:"is_ipv4,omitempty"`
	Origin           string `json:"origin,omitempty"`
	ASPath           string `json:"as_path,omitempty"`
	ASPathCount      int32  `json:"as_path_count,omitempty"`
	OriginAS         string `json:"origin_as,omitempty"`
	Nexthop          string `json:"nexthop,omitempty"`
	MED              uint32 `json:"med,omitempty"`
	LocalPref        uint32 `json:"local_pref,omitempty"`
	Aggregator       string `json:"aggregator,omitempty"`
	CommunityList    string `json:"community_list,omitempty"`
	ExtCommunityList string `json:"ext_community_list,omitempty"`
	IsAtomicAgg      bool   `json:"is_atomic_agg,omitempty"`
	IsNexthopIPv4    bool   `json:"is_nexthop_ipv4,omitempty"`
	OriginatorID     string `json:"originator_id,omitempty"`
	PathID           int32  `json:"path_id,omitempty"`
	Labels           string `json:"labels,omitempty"`
	IsPrepolicy      bool   `json:"isprepolicy,omitempty"`
	IsAdjRIBIn       bool   `json:"is_adj_rib_in,omitempty"`
}

// LSNode defines a structure of LS Node message
type LSNode struct {
	Action              string `json:"action"` // Action can be "add" or "del"
	Sequence            int    `json:"sequence,omitempty"`
	Hash                string `json:"hash,omitempty"`
	RouterHash          string `json:"router_hash,omitempty"`
	RouterIP            string `json:"router_ip,omitempty"`
	BaseAttrHash        string `json:"base_attr_hash,omitempty"`
	PeerHash            string `json:"peer_hash,omitempty"`
	PeerIP              string `json:"peer_ip,omitempty"`
	PeerASN             int32  `json:"peer_asn,omitempty"`
	Timestamp           string `json:"timestamp,omitempty"`
	IGPRouterID         string `json:"igp_router_id,omitempty"`
	RouterID            string `json:"router_id,omitempty"`
	RoutingID           string `json:"routing_id,omitempty"`
	ASN                 uint32 `json:"asn,omitempty"`
	LSID                uint32 `json:"ls_id,omitempty"`
	MTID                string `json:"mt_id,omitempty"`
	OSPFAreaID          string `json:"ospf_area_id,omitempty"`
	ISISAreaID          string `json:"isis_area_id,omitempty"`
	Protocol            string `json:"protocol,omitempty"`
	Flags               uint8  `json:"flags,omitempty"`
	ASPath              string `json:"as_path,omitempty"`
	Nexthop             string `json:"nexthop,omitempty"`
	MED                 uint32 `json:"med,omitempty"`
	LocalPref           uint32 `json:"local_pref,omitempty"`
	Name                string `json:"name,omitempty"`
	SRCapabilities      string `json:"ls_sr_capabilities,omitempty"`
	SRAlgorithm         []int  `json:"sr_algorithm,omitempty"`
	SRLocalBlock        string `json:"sr_local_block,omitempty"`
	SRv6CapabilitiesTLV string `json:"srv6_capabilities_tlv,omitempty"`
	NodeMSD             string `json:"node_msd,omitempty"`
	IsPrepolicy         bool   `json:"isprepolicy,omitempty"`
	IsAdjRIBIn          bool   `json:"is_adj_rib_in,omitempty"`
}

// LSLink defines a structure of LS link message
type LSLink struct {
	Action                string            `json:"action"`
	Sequence              int               `json:"sequence,omitempty"`
	Hash                  string            `json:"hash,omitempty"`
	RouterHash            string            `json:"router_hash,omitempty"`
	RouterIP              string            `json:"router_ip,omitempty"`
	BaseAttrHash          string            `json:"base_attr_hash,omitempty"`
	PeerHash              string            `json:"peer_hash,omitempty"`
	PeerIP                string            `json:"peer_ip,omitempty"`
	PeerASN               int32             `json:"peer_asn,omitempty"`
	Timestamp             string            `json:"timestamp,omitempty"`
	IGPRouterID           string            `json:"igp_router_id,omitempty"`
	RouterID              string            `json:"router_id,omitempty"`
	RoutingID             string            `json:"routing_id,omitempty"`
	LSID                  uint32            `json:"ls_id,omitempty"`
	OSPFAreaID            string            `json:"ospf_area_id,omitempty"`
	ISISAreaID            string            `json:"isis_area_id,omitempty"`
	Protocol              string            `json:"protocol,omitempty"`
	ASPath                string            `json:"as_path,omitempty"`
	LocalPref             uint32            `json:"local_pref,omitempty"`
	MED                   uint32            `json:"med,omitempty"`
	Nexthop               string            `json:"nexthop,omitempty"`
	MTID                  string            `json:"mt_id,omitempty"`
	LocalLinkID           string            `json:"local_link_id,omitempty"`
	RemoteLinkID          string            `json:"remote_link_id,omitempty"`
	InterfaceIP           string            `json:"intf_ip,omitempty"`
	NeighborIP            string            `json:"nei_ip,omitempty"`
	IGPMetric             uint32            `json:"igp_metric,omitempty"`
	AdminGroup            uint32            `json:"admin_group,omitempty"`
	MaxLinkBW             uint32            `json:"max_link_bw,omitempty"`
	MaxResvBW             uint32            `json:"max_resv_bw,omitempty"`
	UnResvBW              []uint32          `json:"unresv_bw,omitempty"`
	TEDefaultMetric       uint32            `json:"te_default_metric,omitempty"`
	LinkProtection        uint16            `json:"link_protection,omitempty"`
	MPLSProtoMask         uint8             `json:"mpls_proto_mask,omitempty"`
	SRLG                  []uint32          `json:"srlg,omitempty"`
	LinkName              string            `json:"link_name,omitempty"`
	RemoteNodeHash        string            `json:"remote_node_hash,omitempty"`
	LocalNodeHash         string            `json:"local_node_hash,omitempty"`
	RemoteIGPRouterID     string            `json:"remote_igp_router_id,omitempty"`
	RemoteRouterID        string            `json:"remote_router_id,omitempty"`
	LocalNodeASN          uint32            `json:"local_node_asn,omitempty"`
	RemoteNodeASN         uint32            `json:"remote_node_asn,omitempty"`
	PeerNodeSID           *srv6.PeerNodeSID `json:"peer_node_sid,omitempty"`
	IsPrepolicy           bool              `json:"isprepolicy,omitempty"`
	IsAdjRIBIn            bool              `json:"is_adj_rib_in,omitempty"`
	LSAdjacencySID        string            `json:"ls_adjacency_sid,omitempty"`
	LinkMSD               string            `json:"link_msd,omitempty"`
	UnidirLinkDelay       uint32            `json:"unidir_link_delay,omitempty"`
	UnidirLinkDelayMinMax []uint32          `json:"unidir_link_delay_min_max,omitempty"`
	UnidirDelayVariation  uint32            `json:"unidir_delay_variation,omitempty"`
	UnidirPacketLoss      uint32            `json:"unidir_packet_loss,omitempty"`
	UnidirResidualBW      uint32            `json:"unidir_residual_bw,omitempty"`
	UnidirAvailableBW     uint32            `json:"unidir_available_bw,omitempty"`
	UnidirBWUtilization   uint32            `json:"unidir_bw_utilization,omitempty"`
}
