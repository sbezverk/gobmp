package message

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/gobmp/pkg/tools"
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
	glog.Infof("><LSNode> UnmarshalJSON called: %s", tools.MessageHex(b))
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
			glog.Errorf("BuildSRCapability failed with error: %+v", err)
			return err
		}
		n.SRCapabilities = cap
	}

	return nil
}

// UnmarshalJSON is a custom unmarshaller for LSLink struct
func (l *LSLink) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	if v, ok := objmap["action"]; ok {
		if err := json.Unmarshal(v, &l.Action); err != nil {
			return err
		}
	}
	if v, ok := objmap["sequence"]; ok {
		if err := json.Unmarshal(v, &l.Sequence); err != nil {
			return err
		}
	}
	if v, ok := objmap["router_hash"]; ok {
		if err := json.Unmarshal(v, &l.RouterHash); err != nil {
			return err
		}
	}
	if v, ok := objmap["router_ip"]; ok {
		if err := json.Unmarshal(v, &l.RouterIP); err != nil {
			return err
		}
	}
	if v, ok := objmap["base_attrs"]; ok {
		l.BaseAttributes = &bgp.BaseAttributes{}
		if err := json.Unmarshal(v, &l.BaseAttributes); err != nil {
			return err
		}
	}
	if v, ok := objmap["peer_hash"]; ok {
		if err := json.Unmarshal(v, &l.PeerHash); err != nil {
			return err
		}
	}
	if v, ok := objmap["peer_ip"]; ok {
		if err := json.Unmarshal(v, &l.PeerIP); err != nil {
			return err
		}
	}
	if v, ok := objmap["peer_asn"]; ok {
		if err := json.Unmarshal(v, &l.PeerASN); err != nil {
			return err
		}
	}
	if v, ok := objmap["timestamp"]; ok {
		if err := json.Unmarshal(v, &l.Timestamp); err != nil {
			return err
		}
	}
	if v, ok := objmap["igp_router_id"]; ok {
		if err := json.Unmarshal(v, &l.IGPRouterID); err != nil {
			return err
		}
	}
	if v, ok := objmap["remote_igp_router_id"]; ok {
		if err := json.Unmarshal(v, &l.RemoteIGPRouterID); err != nil {
			return err
		}
	}
	if v, ok := objmap["router_id"]; ok {
		if err := json.Unmarshal(v, &l.RouterID); err != nil {
			return err
		}
	}
	if v, ok := objmap["remote_router_id"]; ok {
		if err := json.Unmarshal(v, &l.RemoteRouterID); err != nil {
			return err
		}
	}
	if v, ok := objmap["routing_id"]; ok {
		if err := json.Unmarshal(v, &l.RoutingID); err != nil {
			return err
		}
	}
	if v, ok := objmap["local_node_asn"]; ok {
		if err := json.Unmarshal(v, &l.LocalNodeASN); err != nil {
			return err
		}
	}
	if v, ok := objmap["remote_node_asn"]; ok {
		if err := json.Unmarshal(v, &l.RemoteNodeASN); err != nil {
			return err
		}
	}

	if v, ok := objmap["ls_id"]; ok {
		if err := json.Unmarshal(v, &l.LSID); err != nil {
			return err
		}
	}
	if v, ok := objmap["protocol_id"]; ok {
		if err := json.Unmarshal(v, &l.ProtocolID); err != nil {
			return err
		}
	}
	if v, ok := objmap["protocol"]; ok {
		if err := json.Unmarshal(v, &l.Protocol); err != nil {
			return err
		}
	}
	if v, ok := objmap["nexthop"]; ok {
		if err := json.Unmarshal(v, &l.Nexthop); err != nil {
			return err
		}
	}
	if v, ok := objmap["local_node_hash"]; ok {
		if err := json.Unmarshal(v, &l.LocalNodeHash); err != nil {
			return err
		}
	}
	if v, ok := objmap["mt_id"]; ok {
		if err := json.Unmarshal(v, &l.MTID); err != nil {
			return err
		}
	}
	if v, ok := objmap["local_link_id"]; ok {
		if err := json.Unmarshal(v, &l.LocalLinkID); err != nil {
			return err
		}
	}
	if v, ok := objmap["remote_link_id"]; ok {
		if err := json.Unmarshal(v, &l.RemoteLinkID); err != nil {
			return err
		}
	}
	if v, ok := objmap["intf_ip"]; ok {
		if err := json.Unmarshal(v, &l.InterfaceIP); err != nil {
			return err
		}
	}
	if v, ok := objmap["nei_ip"]; ok {
		if err := json.Unmarshal(v, &l.NeighborIP); err != nil {
			return err
		}
	}
	if v, ok := objmap["igp_metric"]; ok {
		if err := json.Unmarshal(v, &l.IGPMetric); err != nil {
			return err
		}
	}
	if v, ok := objmap["admin_group"]; ok {
		if err := json.Unmarshal(v, &l.AdminGroup); err != nil {
			return err
		}
	}
	if v, ok := objmap["max_link_bw"]; ok {
		if err := json.Unmarshal(v, &l.MaxLinkBW); err != nil {
			return err
		}
	}
	if v, ok := objmap["max_resv_bw"]; ok {
		if err := json.Unmarshal(v, &l.MaxResvBW); err != nil {
			return err
		}
	}
	if v, ok := objmap["unresv_bw"]; ok {
		if err := json.Unmarshal(v, &l.UnResvBW); err != nil {
			return err
		}
	}
	if v, ok := objmap["te_default_metric"]; ok {
		if err := json.Unmarshal(v, &l.TEDefaultMetric); err != nil {
			return err
		}
	}
	if v, ok := objmap["link_protection"]; ok {
		if err := json.Unmarshal(v, &l.LinkProtection); err != nil {
			return err
		}
	}
	if v, ok := objmap["mpls_proto_mask"]; ok {
		if err := json.Unmarshal(v, &l.MPLSProtoMask); err != nil {
			return err
		}
	}
	if v, ok := objmap["srlg"]; ok {
		if err := json.Unmarshal(v, &l.SRLG); err != nil {
			return err
		}
	}
	if v, ok := objmap["link_name"]; ok {
		if err := json.Unmarshal(v, &l.LinkName); err != nil {
			return err
		}
	}

	if v, ok := objmap["remote_node_hash"]; ok {
		if err := json.Unmarshal(v, &l.RemoteNodeHash); err != nil {
			return err
		}
	}
	if v, ok := objmap["local_node_hash"]; ok {
		if err := json.Unmarshal(v, &l.LocalNodeHash); err != nil {
			return err
		}
	}
	if v, ok := objmap["srv6_bgp_peer_node_sid"]; ok {
		l.SRv6BGPPeerNodeSID = &srv6.BGPPeerNodeSID{}
		if err := json.Unmarshal(v, &l.SRv6BGPPeerNodeSID); err != nil {
			return err
		}
	}
	if v, ok := objmap["srv6_endx_sid"]; ok {
		l.SRv6ENDXSID = &srv6.EndXSIDTLV{}
		if err := json.Unmarshal(v, &l.SRv6ENDXSID); err != nil {
			return err
		}
	}
	l.IsPrepolicy = false
	if v, ok := objmap["isprepolicy"]; ok {
		if err := json.Unmarshal(v, &l.IsPrepolicy); err != nil {
			return err
		}
	}
	l.IsAdjRIBIn = false
	if v, ok := objmap["is_adj_rib_in"]; ok {
		if err := json.Unmarshal(v, &l.IsAdjRIBIn); err != nil {
			return err
		}
	}
	if v, ok := objmap["ls_adjacency_sid"]; ok {
		l.LSAdjacencySID = make([]*sr.AdjacencySIDTLV, 0)
		var f []map[string]json.RawMessage
		if err := json.Unmarshal(v, &f); err != nil {
			return err
		}
		for _, e := range f {
			as, err := sr.BuildAdjacencySID(l.ProtocolID, e)
			if err != nil {
				return err
			}
			l.LSAdjacencySID = append(l.LSAdjacencySID, as)
		}
	}
	if v, ok := objmap["link_msd"]; ok {
		if err := json.Unmarshal(v, &l.LinkMSD); err != nil {
			return err
		}
	}
	if v, ok := objmap["unidir_link_delay"]; ok {
		if err := json.Unmarshal(v, &l.UnidirLinkDelay); err != nil {
			return err
		}
	}
	if v, ok := objmap["unidir_link_delay_min_max"]; ok {
		if err := json.Unmarshal(v, &l.UnidirLinkDelayMinMax); err != nil {
			return err
		}
	}
	if v, ok := objmap["unidir_delay_variation"]; ok {
		if err := json.Unmarshal(v, &l.UnidirDelayVariation); err != nil {
			return err
		}
	}
	if v, ok := objmap["unidir_packet_loss"]; ok {
		if err := json.Unmarshal(v, &l.UnidirPacketLoss); err != nil {
			return err
		}
	}
	if v, ok := objmap["unidir_residual_bw"]; ok {
		if err := json.Unmarshal(v, &l.UnidirPacketLoss); err != nil {
			return err
		}
	}
	if v, ok := objmap["unidir_available_bw"]; ok {
		if err := json.Unmarshal(v, &l.UnidirPacketLoss); err != nil {
			return err
		}
	}
	if v, ok := objmap["unidir_bw_utilization"]; ok {
		if err := json.Unmarshal(v, &l.UnidirBWUtilization); err != nil {
			return err
		}
	}
	return nil
}
