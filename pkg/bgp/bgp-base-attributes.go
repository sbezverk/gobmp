package bgp

// BaseAttributes defines a structure holding BGP's basic, non nlri based attributes,
// codes for each can be found:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2
type BaseAttributes struct {
	BaseAttrHash  string   `json:"base_attr_hash,omitempty"`
	Origin        string   `json:"origin,omitempty"`
	ASPath        []uint32 `json:"as_path,omitempty"`
	ASPathCount   int32    `json:"as_path_count,omitempty"`
	Nexthop       string   `json:"nexthop,omitempty"`
	MED           uint32   `json:"med,omitempty"`
	LocalPref     uint32   `json:"local_pref,omitempty"`
	IsAtomicAgg   bool     `json:"is_atomic_agg"`
	Aggregator    string   `json:"aggregator,omitempty"`
	CommunityList string   `json:"community_list,omitempty"`
	OriginatorID  string   `json:"originator_id,omitempty"`
	// ClusterList
	ExtCommunityList string `json:"ext_community_list,omitempty"`
	// AS4Path
	// AS4PathCount
	// AS4Aggregator
	// PMSITunnel
	// TunnelEncapAttr
	// TraficEng
	// IPv6SpecExtCommunity
	// AIGP
	// PEDistinguisherLable
	LgCommunityList string `json:"large_community_list,omitempty"`
	// SecPath
	// AttrSet
}

// UnmarshalBGPBaseAttributes discovers all present Base Attributes in BGP Update
// and instantiates BaseAttributes object
func UnmarshalBGPBaseAttributes(b []byte) (*BaseAttributes, err) {

	return nil, nil
}
