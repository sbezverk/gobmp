package message

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

func (p *producer) lsPrefix(prfx *base.PrefixNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update, ipv4 bool) (*LSPrefix, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}
	msg := LSPrefix{
		Action:     operation,
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
		PeerHash:   ph.GetPeerHash(),
		PeerASN:    ph.PeerAS,
		Timestamp:  ph.GetPeerTimestamp(),
		DomainID:   prfx.GetIdentifier(),
	}
	msg.Nexthop = nextHop
	msg.PeerIP = ph.GetPeerAddrString()
	msg.ProtocolID = prfx.ProtocolID
	msg.Protocol = prfx.GetPrefixProtocolID()
	msg.LSID = prfx.GetPrefixLSID()
	msg.LocalNodeHash = prfx.LocalNodeHash
	msg.IGPRouterID = prfx.GetLocalIGPRouterID()
	msg.MTID = prfx.Prefix.GetPrefixMTID()
	route := prfx.Prefix.GetPrefixIPReachability(ipv4)
	msg.PrefixLen = int32(route.Length)
	pr := prfx.Prefix.GetPrefixIPReachability(ipv4).Prefix
	if !ipv4 {
		msg.Prefix = net.IP(pr).To16().String()
	} else {
		msg.Prefix = net.IP(pr).To4().String()
	}
	switch prfx.ProtocolID {
	case base.ISISL1:
		fallthrough
	case base.ISISL2:
		// Proposed by Peter Psenak <ppsenak@cisco.com>
		// 1027 TLV is not sent for ISIS links/prefixes, because ISIS has no
		// concept of areas. The proposal is to use generic representation,
		// so include area-id and always set to 0 for ISIS.
		msg.AreaID = "0"
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		msg.OSPFRouteType = prfx.Prefix.GetPrefixOSPFRouteType()
		msg.AreaID = prfx.LocalNode.GetOSPFAreaID()
	default:
		msg.AreaID = "0"
	}
	lsprefix, err := update.GetNLRI29()
	if err == nil {
		if ph.FlagV {
			msg.RouterID = lsprefix.GetLocalIPv6RouterID()
		} else {
			msg.RouterID = lsprefix.GetLocalIPv4RouterID()
		}
		msg.PrefixMetric = lsprefix.GetPrefixMetric()
		msg.IGPMetric = lsprefix.GetIGPMetric()
		msg.IGPRouteTag = lsprefix.GetPrefixIGPRouteTag()
		msg.IGPExtRouteTag = lsprefix.GetPrefixIGPExtRouteTag()
		if ps, err := lsprefix.GetLSPrefixSID(prfx.ProtocolID); err == nil {
			msg.LSPrefixSID = ps
		}
		if paf, err := lsprefix.GetLSPrefixAttrFlags(); err == nil {
			msg.PrefixAttrFlags = paf
		}
		if fap, err := lsprefix.GetFlexAlgoPrefixMetric(); err == nil {
			msg.FlexAlgoPrefixMetric = fap
		}
		if loc, err := lsprefix.GetLSSRv6Locator(); err == nil {
			msg.SRv6Locator = loc
		}
		if s, err := lsprefix.GetLSSourceRouterID(); err == nil {
			msg.SourceRouterID = s
		}
	}

	return &msg, nil
}

func (p *LSPrefix) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	np := &LSPrefix{}
	// Key                  string                        `json:"_key,omitempty"`
	if v, ok := objmap["_key"]; ok {
		if err := json.Unmarshal(v, &np.Key); err != nil {
			return err
		}
	}
	// ID                   string                        `json:"_id,omitempty"`
	if v, ok := objmap["_id"]; ok {
		if err := json.Unmarshal(v, &np.ID); err != nil {
			return err
		}
	}
	// Rev                  string                        `json:"_rev,omitempty"`
	if v, ok := objmap["_rev"]; ok {
		if err := json.Unmarshal(v, &np.Rev); err != nil {
			return err
		}
	}
	// Action               string                        `json:"action,omitempty"`
	if v, ok := objmap["action"]; ok {
		if err := json.Unmarshal(v, &np.Action); err != nil {
			return err
		}
	}
	// Sequence             int                           `json:"sequence,omitempty"`
	if v, ok := objmap["sequence"]; ok {
		if err := json.Unmarshal(v, &np.Sequence); err != nil {
			return err
		}
	}
	// Hash                 string                        `json:"hash,omitempty"`
	if v, ok := objmap["hash"]; ok {
		if err := json.Unmarshal(v, &np.Hash); err != nil {
			return err
		}
	}
	// RouterHash           string                        `json:"router_hash,omitempty"`
	if v, ok := objmap["router_hash"]; ok {
		if err := json.Unmarshal(v, &np.RouterHash); err != nil {
			return err
		}
	}
	// RouterIP             string                        `json:"router_ip,omitempty"`
	if v, ok := objmap["router_ip"]; ok {
		if err := json.Unmarshal(v, &np.RouterIP); err != nil {
			return err
		}
	}
	// DomainID             int64                         `json:"domain_id"`
	if v, ok := objmap["domain_id"]; ok {
		if err := json.Unmarshal(v, &np.DomainID); err != nil {
			return err
		}
	}
	// PeerHash             string                        `json:"peer_hash,omitempty"`
	if v, ok := objmap["peer_hash"]; ok {
		if err := json.Unmarshal(v, &np.PeerHash); err != nil {
			return err
		}
	}
	// PeerIP               string                        `json:"peer_ip,omitempty"`
	if v, ok := objmap["peer_ip"]; ok {
		if err := json.Unmarshal(v, &np.PeerIP); err != nil {
			return err
		}
	}
	// PeerASN              int32                         `json:"peer_asn,omitempty"`
	if v, ok := objmap["peer_asn"]; ok {
		if err := json.Unmarshal(v, &np.PeerASN); err != nil {
			return err
		}
	}
	// Timestamp            string                        `json:"timestamp,omitempty"`
	if v, ok := objmap["timestamp"]; ok {
		if err := json.Unmarshal(v, &np.Timestamp); err != nil {
			return err
		}
	}
	// IGPRouterID          string                        `json:"igp_router_id,omitempty"`
	if v, ok := objmap["igp_router_id"]; ok {
		if err := json.Unmarshal(v, &np.IGPRouterID); err != nil {
			return err
		}
	}
	// RouterID             string                        `json:"router_id,omitempty"`
	if v, ok := objmap["router_id"]; ok {
		if err := json.Unmarshal(v, &np.RouterID); err != nil {
			return err
		}
	}
	// LSID                 uint32                        `json:"ls_id,omitempty"`
	if v, ok := objmap["ls_id"]; ok {
		if err := json.Unmarshal(v, &np.LSID); err != nil {
			return err
		}
	}
	// ProtocolID           base.ProtoID                  `json:"protocol_id,omitempty"`
	if v, ok := objmap["protocol_id"]; ok {
		if err := json.Unmarshal(v, &np.ProtocolID); err != nil {
			return err
		}
	}
	// Protocol             string                        `json:"protocol,omitempty"`
	if v, ok := objmap["protocol"]; ok {
		if err := json.Unmarshal(v, &np.Protocol); err != nil {
			return err
		}
	}
	// AreaID               string                        `json:"area_id"`
	if v, ok := objmap["area_id"]; ok {
		if err := json.Unmarshal(v, &np.AreaID); err != nil {
			return err
		}
	}
	// Nexthop              string                        `json:"nexthop,omitempty"`
	if v, ok := objmap["router_ip"]; ok {
		if err := json.Unmarshal(v, &np.RouterIP); err != nil {
			return err
		}
	}
	// LocalNodeHash        string                        `json:"local_node_hash,omitempty"`
	if v, ok := objmap["local_node_hash"]; ok {
		if err := json.Unmarshal(v, &np.LocalNodeHash); err != nil {
			return err
		}
	}
	// MTID                 *base.MultiTopologyIdentifier `json:"mt_id_tlv,omitempty"`
	if v, ok := objmap["mt_id_tlv"]; ok {
		if err := json.Unmarshal(v, &np.MTID); err != nil {
			return err
		}
	}
	// OSPFRouteType        uint8                         `json:"ospf_route_type,omitempty"`
	if v, ok := objmap["ospf_route_type"]; ok {
		if err := json.Unmarshal(v, &np.OSPFRouteType); err != nil {
			return err
		}
	}
	// IGPFlags             uint8                         `json:"igp_flags"`
	if v, ok := objmap["igp_flags"]; ok {
		if err := json.Unmarshal(v, &np.IGPFlags); err != nil {
			return err
		}
	}
	// IGPRouteTag          []uint32                      `json:"route_tag,omitempty"`
	if v, ok := objmap["route_tag"]; ok {
		var rt []uint32
		if err := json.Unmarshal(v, &rt); err != nil {
			return err
		}
		np.IGPRouteTag = rt
	}
	// IGPExtRouteTag       []uint64                      `json:"ext_route_tag,omitempty"`
	if v, ok := objmap["ext_route_tag"]; ok {
		var rt []uint64
		if err := json.Unmarshal(v, &rt); err != nil {
			return err
		}
		np.IGPExtRouteTag = rt
	}
	// OSPFFwdAddr          string                        `json:"ospf_fwd_addr,omitempty"`
	if v, ok := objmap["ospf_fwd_addr"]; ok {
		if err := json.Unmarshal(v, &np.OSPFFwdAddr); err != nil {
			return err
		}
	}
	// IGPMetric            uint32                        `json:"igp_metric,omitempty"`
	if v, ok := objmap["igp_metric"]; ok {
		if err := json.Unmarshal(v, &np.IGPMetric); err != nil {
			return err
		}
	}
	// Prefix               string                        `json:"prefix,omitempty"`
	if v, ok := objmap["prefix"]; ok {
		if err := json.Unmarshal(v, &np.Prefix); err != nil {
			return err
		}
	}
	// PrefixLen            int32                         `json:"prefix_len,omitempty"`
	if v, ok := objmap["prefix_len"]; ok {
		if err := json.Unmarshal(v, &np.PrefixLen); err != nil {
			return err
		}
	}
	// PrefixMetric         uint32                        `json:"prefix_metric,omitempty"`
	if v, ok := objmap["prefix_metric"]; ok {
		if err := json.Unmarshal(v, &np.PrefixMetric); err != nil {
			return err
		}
	}
	// IsPrepolicy          bool                          `json:"is_prepolicy"`
	if v, ok := objmap["is_prepolicy"]; ok {
		if err := json.Unmarshal(v, &np.IsPrepolicy); err != nil {
			return err
		}
	}
	// IsAdjRIBIn           bool                          `json:"is_adj_rib_in"`
	if v, ok := objmap["is_adj_rib_in"]; ok {
		if err := json.Unmarshal(v, &np.IsAdjRIBIn); err != nil {
			return err
		}
	}
	// LSPrefixSID          []*sr.PrefixSIDTLV            `json:"ls_prefix_sid,omitempty"`
	if v, ok := objmap["ls_prefix_sid"]; ok {
		rt := make([]*sr.PrefixSIDTLV, 0)
		var objmap []map[string]json.RawMessage
		if err := json.Unmarshal(v, &objmap); err != nil {
			return err
		}
		for _, objVal := range objmap {
			pr := &sr.PrefixSIDTLV{}
			// Flags     PrefixSIDFlags `json:"flags,omitempty"`
			if v, ok := objVal["flags"]; ok {
				switch np.ProtocolID {
				case base.ISISL1:
					fallthrough
				case base.ISISL2:
					f := &sr.ISISFlags{}
					if err := json.Unmarshal(v, &f); err != nil {
						return err
					}
					pr.Flags = f
				case base.OSPFv2:
					fallthrough
				case base.OSPFv3:
					f := &sr.OSPFFlags{}
					if err := json.Unmarshal(v, &f); err != nil {
						return err
					}
					pr.Flags = f
				default:
					f := &sr.UnknownProtoFlags{}
					if err := json.Unmarshal(v, &f); err != nil {
						return err
					}
					pr.Flags = f

				}
			}
			// Algorithm uint8          `json:"algo"`
			if v, ok := objVal["algo"]; ok {
				if err := json.Unmarshal(v, &pr.Algorithm); err != nil {
					return err
				}
			}
			// SID       uint32         `json:"prefix_sid,omitempty"`
			if v, ok := objVal["prefix_sid"]; ok {
				if err := json.Unmarshal(v, &pr.SID); err != nil {
					return err
				}
			}
			rt = append(rt, pr)
		}
		np.LSPrefixSID = rt
	}
	// PrefixAttrFlags      uint8                         `json:"prefix_attr_flags"`
	if v, ok := objmap["prefix_attr_flags"]; ok {
		if err := json.Unmarshal(v, &np.PrefixAttrFlags); err != nil {
			return err
		}
	}
	// FlexAlgoPrefixMetric []*bgpls.FlexAlgoPrefixMetric `json:"flex_algo_prefix_metric,omitempty"`
	if v, ok := objmap["flex_algo_prefix_metric"]; ok {
		var rt []*bgpls.FlexAlgoPrefixMetric
		if err := json.Unmarshal(v, &rt); err != nil {
			return err
		}
		np.FlexAlgoPrefixMetric = rt
	}
	// SRv6Locator          []*srv6.LocatorTLV            `json:"srv6_locator,omitempty"`
	if v, ok := objmap["srv6_locator"]; ok {
		var rt []*srv6.LocatorTLV
		if err := json.Unmarshal(v, &rt); err != nil {
			return err
		}
		np.SRv6Locator = rt
	}
	// SourceRouterID       string                        `json:"source_router_id,omitempty"`
	if v, ok := objmap["source_router_id"]; ok {
		if err := json.Unmarshal(v, &np.SourceRouterID); err != nil {
			return err
		}
	}
	*p = *np

	return nil
}
