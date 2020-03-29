package message

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
	MED              int32  `json:"med,omitempty"`
	LocalPref        int32  `json:"local_pref,omitempty"`
	Aggregator       string `json:"aggregator,omitempty"`
	CommunityList    string `json:"community_list,omitempty"`
	ExtCommunityList string `json:"ext_community_list,omitempty"`
	IsAtomicAgg      bool   `json:"is_atomic_agg,omitempty"`
	IsNexthopIPv4    bool   `json:"is_nexthop_ipv4,omitempty"`
	OriginatorID     int32  `json:"originator_id,omitempty"`
	PathID           int32  `json:"path_id,omitempty"`
	Labels           string `json:"labels,omitempty"`
	IsPrepolicy      bool   `json:"isprepolicy,omitempty"`
	IsAdjRIBIn       bool   `json:"is_adj_rib_in,omitempty"`
}
