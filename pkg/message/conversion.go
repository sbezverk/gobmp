package message

import (
	"encoding/json"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/sr"
)

// UnmarshalJSON is a custom unmarshaller for LSPrefix struct
func (p *LSPrefix) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	if v, ok := objmap["action"]; ok {
		if err := json.Unmarshal(v, &p.Action); err != nil {
			return err
		}
	}
	if v, ok := objmap["sequence"]; ok {
		if err := json.Unmarshal(v, &p.Sequence); err != nil {
			return err
		}
	}
	if v, ok := objmap["router_hash"]; ok {
		if err := json.Unmarshal(v, &p.RouterHash); err != nil {
			return err
		}
	}
	if v, ok := objmap["router_ip"]; ok {
		if err := json.Unmarshal(v, &p.RouterIP); err != nil {
			return err
		}
	}
	if v, ok := objmap["base_attrs"]; ok {
		p.BaseAttributes = &bgp.BaseAttributes{}
		if err := json.Unmarshal(v, &p.BaseAttributes); err != nil {
			return err
		}
	}
	if v, ok := objmap["peer_hash"]; ok {
		if err := json.Unmarshal(v, &p.PeerHash); err != nil {
			return err
		}
	}
	if v, ok := objmap["peer_ip"]; ok {
		if err := json.Unmarshal(v, &p.PeerIP); err != nil {
			return err
		}
	}
	if v, ok := objmap["peer_asn"]; ok {
		if err := json.Unmarshal(v, &p.PeerASN); err != nil {
			return err
		}
	}
	if v, ok := objmap["timestamp"]; ok {
		if err := json.Unmarshal(v, &p.Timestamp); err != nil {
			return err
		}
	}
	if v, ok := objmap["igp_router_id"]; ok {
		if err := json.Unmarshal(v, &p.IGPRouterID); err != nil {
			return err
		}
	}
	if v, ok := objmap["router_id"]; ok {
		if err := json.Unmarshal(v, &p.RouterID); err != nil {
			return err
		}
	}
	if v, ok := objmap["routing_id"]; ok {
		if err := json.Unmarshal(v, &p.RoutingID); err != nil {
			return err
		}
	}
	if v, ok := objmap["ls_id"]; ok {
		if err := json.Unmarshal(v, &p.LSID); err != nil {
			return err
		}
	}
	if v, ok := objmap["protocol_id"]; ok {
		if err := json.Unmarshal(v, &p.ProtocolID); err != nil {
			return err
		}
	}
	if v, ok := objmap["protocol"]; ok {
		if err := json.Unmarshal(v, &p.Protocol); err != nil {
			return err
		}
	}
	if v, ok := objmap["nexthop"]; ok {
		if err := json.Unmarshal(v, &p.Nexthop); err != nil {
			return err
		}
	}
	if v, ok := objmap["local_node_hash"]; ok {
		if err := json.Unmarshal(v, &p.LocalNodeHash); err != nil {
			return err
		}
	}
	if v, ok := objmap["mt_id"]; ok {
		if err := json.Unmarshal(v, &p.MTID); err != nil {
			return err
		}
	}
	if v, ok := objmap["ospf_route_type"]; ok {
		if err := json.Unmarshal(v, &p.OSPFRouteType); err != nil {
			return err
		}
	}
	if v, ok := objmap["igp_flags"]; ok {
		if err := json.Unmarshal(v, &p.IGPFlags); err != nil {
			return err
		}
	}
	if v, ok := objmap["route_tag"]; ok {
		if err := json.Unmarshal(v, &p.RouteTag); err != nil {
			return err
		}
	}
	if v, ok := objmap["ext_route_tag"]; ok {
		if err := json.Unmarshal(v, &p.ExtRouteTag); err != nil {
			return err
		}
	}
	if v, ok := objmap["ospf_fwd_addr"]; ok {
		if err := json.Unmarshal(v, &p.OSPFFwdAddr); err != nil {
			return err
		}
	}
	if v, ok := objmap["igp_metric"]; ok {
		if err := json.Unmarshal(v, &p.IGPMetric); err != nil {
			return err
		}
	}
	if v, ok := objmap["prefix"]; ok {
		if err := json.Unmarshal(v, &p.Prefix); err != nil {
			return err
		}
	}
	if v, ok := objmap["prefix_len"]; ok {
		if err := json.Unmarshal(v, &p.PrefixLen); err != nil {
			return err
		}
	}
	p.IsPrepolicy = false
	if v, ok := objmap["isprepolicy"]; ok {
		if err := json.Unmarshal(v, &p.IsPrepolicy); err != nil {
			return err
		}
	}
	p.IsAdjRIBIn = false
	if v, ok := objmap["is_adj_rib_in"]; ok {
		if err := json.Unmarshal(v, &p.IsAdjRIBIn); err != nil {
			return err
		}
	}
	if v, ok := objmap["ls_prefix_sid"]; ok {
		p.LSPrefixSID = make([]*sr.PrefixSIDTLV, 0)
		var f []map[string]json.RawMessage
		if err := json.Unmarshal(v, &f); err != nil {
			return err
		}
		for _, e := range f {
			ps, err := sr.BuildPrefixSID(p.ProtocolID, e)
			if err != nil {
				return err
			}
			p.LSPrefixSID = append(p.LSPrefixSID, ps)
		}
	}
	if v, ok := objmap["prefix_attr_flags"]; ok {
		paf, err := base.BuildPrefixAttrFlags(p.ProtocolID, v)
		if err != nil {
			return err
		}
		p.PrefixAttrFlags = paf
	}

	return nil
}

// UnmarshalJSON is a custom unmarshaller for LSPrefix struct
func (n *LSNode) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	if v, ok := objmap["action"]; ok {
		if err := json.Unmarshal(v, &n.Action); err != nil {
			return err
		}
	}
	if v, ok := objmap["sequence"]; ok {
		if err := json.Unmarshal(v, &n.Sequence); err != nil {
			return err
		}
	}
	if v, ok := objmap["router_hash"]; ok {
		if err := json.Unmarshal(v, &n.RouterHash); err != nil {
			return err
		}
	}
	if v, ok := objmap["router_ip"]; ok {
		if err := json.Unmarshal(v, &n.RouterIP); err != nil {
			return err
		}
	}
	if v, ok := objmap["base_attrs"]; ok {
		n.BaseAttributes = &bgp.BaseAttributes{}
		if err := json.Unmarshal(v, &n.BaseAttributes); err != nil {
			return err
		}
	}
	if v, ok := objmap["peer_hash"]; ok {
		if err := json.Unmarshal(v, &n.PeerHash); err != nil {
			return err
		}
	}
	if v, ok := objmap["peer_ip"]; ok {
		if err := json.Unmarshal(v, &n.PeerIP); err != nil {
			return err
		}
	}
	if v, ok := objmap["peer_asn"]; ok {
		if err := json.Unmarshal(v, &n.PeerASN); err != nil {
			return err
		}
	}
	if v, ok := objmap["timestamp"]; ok {
		if err := json.Unmarshal(v, &n.Timestamp); err != nil {
			return err
		}
	}
	if v, ok := objmap["igp_router_id"]; ok {
		if err := json.Unmarshal(v, &n.IGPRouterID); err != nil {
			return err
		}
	}
	if v, ok := objmap["router_id"]; ok {
		if err := json.Unmarshal(v, &n.RouterID); err != nil {
			return err
		}
	}
	if v, ok := objmap["routing_id"]; ok {
		if err := json.Unmarshal(v, &n.RoutingID); err != nil {
			return err
		}
	}
	if v, ok := objmap["ls_id"]; ok {
		if err := json.Unmarshal(v, &n.LSID); err != nil {
			return err
		}
	}
	if v, ok := objmap["protocol_id"]; ok {
		if err := json.Unmarshal(v, &n.ProtocolID); err != nil {
			return err
		}
	}
	if v, ok := objmap["protocol"]; ok {
		if err := json.Unmarshal(v, &n.Protocol); err != nil {
			return err
		}
	}
	if v, ok := objmap["nexthop"]; ok {
		if err := json.Unmarshal(v, &n.Nexthop); err != nil {
			return err
		}
	}
	if v, ok := objmap["mt_id"]; ok {
		if err := json.Unmarshal(v, &n.MTID); err != nil {
			return err
		}
	}
	if v, ok := objmap["ospf_area_id"]; ok {
		if err := json.Unmarshal(v, &n.OSPFAreaID); err != nil {
			return err
		}
	}
	if v, ok := objmap["isis_area_id"]; ok {
		if err := json.Unmarshal(v, &n.ISISAreaID); err != nil {
			return err
		}
	}
	if v, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(v, &n.Flags); err != nil {
			return err
		}
	}
	if v, ok := objmap["name"]; ok {
		if err := json.Unmarshal(v, &n.Name); err != nil {
			return err
		}
	}
	if v, ok := objmap["sr_algorithm"]; ok {
		if err := json.Unmarshal(v, &n.SRAlgorithm); err != nil {
			return err
		}
	}
	if v, ok := objmap["sr_local_block"]; ok {
		n.SRLocalBlock = &sr.LocalBlock{}
		if err := json.Unmarshal(v, &n.SRLocalBlock); err != nil {
			return err
		}
	}
	if v, ok := objmap["srv6_capabilities_tlv"]; ok {
		if err := json.Unmarshal(v, &n.SRv6CapabilitiesTLV); err != nil {
			return err
		}
	}
	if v, ok := objmap["node_msd"]; ok {
		if err := json.Unmarshal(v, &n.NodeMSD); err != nil {
			return err
		}
	}
	n.IsPrepolicy = false
	if v, ok := objmap["isprepolicy"]; ok {
		if err := json.Unmarshal(v, &n.IsPrepolicy); err != nil {
			return err
		}
	}
	n.IsAdjRIBIn = false
	if v, ok := objmap["is_adj_rib_in"]; ok {
		if err := json.Unmarshal(v, &n.IsAdjRIBIn); err != nil {
			return err
		}
	}
	if v, ok := objmap["ls_sr_capabilities"]; ok {
		cap, err := sr.BuildSRCapability(n.ProtocolID, v)
		if err != nil {
			return err
		}
		n.SRCapabilities = cap
	}

	return nil
}
