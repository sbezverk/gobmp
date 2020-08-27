package message

import (
	"encoding/json"

	"github.com/golang/glog"
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
		if err := json.Unmarshal(v, &p.PeerIP); err != nil {
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
		glog.Infof("><SB> PrefixSID: %+v", v)
	}
	if v, ok := objmap["prefix_attr_flag"]; ok {
		glog.Infof("><SB> PrefixAttrFlags: %+v", v)
	}
	return nil
}
