package message

import (
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/ls"
)

const (
	// AddPrefix defines a const for Add Prefix operation
	AddPrefix = iota
	// DelPrefix defines a const for Delete Prefix operation
	DelPrefix
)

func (p *producer) produceRouteMonitorMessage(msg bmp.Message) {
	var j []byte
	if msg.PeerHeader == nil {
		glog.Errorf("perPeerHeader is missing, cannot construct PeerStateChange message")
		return
	}
	routeMonitorMsg, ok := msg.Payload.(*bmp.RouteMonitor)
	if !ok {
		glog.Errorf("got invalid Payload type in bmp.Message")
		return
	}
	if routeMonitorMsg == nil {
		glog.Errorf("route monitor message is nil")
		return
	}
	if len(routeMonitorMsg.Update.PathAttributes) == 0 {
		// There is no Path Attributes, just return
		return
	}
	glog.V(6).Infof("All attributes in bgp update: %+v", routeMonitorMsg.Update.GetAllAttributeID())
	// ipv4Flag used to differentiate between IPv4 and IPv6 Prefix NLRI messages
	ipv4Flag := false
	// Using first attribute type to select which nlri processor to call
	switch routeMonitorMsg.Update.PathAttributes[0].AttributeType {
	case 14:
		// MP_REACH_NLRI
		t, err := getNLRIMessageType(routeMonitorMsg.Update.PathAttributes)
		if err != nil {
			glog.Errorf("failed to identify exact NLRI type with error: %+v", err)
			return
		}
		switch t {
		case 1:
			glog.Infof("1 IP (IP version 4) : 1 unicast forwarding")
		case 2:
			glog.Infof("2 IP6 (IP version 6) : 1 unicast forwarding")
		case 16:
			glog.Infof("1 IP (IP version 4) : 4 MPLS Labels")
		case 17:
			glog.Infof("2 IP (IP version 6) : 4 MPLS Labels")
		case 18:
			glog.V(6).Infof("1 IP (IP version 4) : 128 MPLS-labeled VPN address")
			msg, err := p.l3vpn(AddPrefix, msg.PeerHeader, routeMonitorMsg.Update)
			if err != nil {
				glog.Errorf("failed to produce l3vpn message with error: %+v", err)
				return
			}
			j, err = json.Marshal(&msg)
			if err != nil {
				glog.Errorf("failed to marshal l3vpn message with error: %+v", err)
				return
			}
			if err := p.publisher.PublishMessage(bmp.L3VPNMsg, []byte(msg.RouterHash), j); err != nil {
				glog.Errorf("failed to push L3VPN message to kafka with error: %+v", err)
				return
			}
			glog.V(6).Infof("l3vpn message: %s", string(j))
		case 19:
			glog.Infof("2 IP (IP version 6) : 128 MPLS-labeled VPN address")
		case 32:
			glog.V(6).Infof("Node NLRI")
			msg, err := p.lsNode("add", msg.PeerHeader, routeMonitorMsg.Update)
			if err != nil {
				glog.Errorf("failed to produce ls_node message with error: %+v", err)
				return
			}
			j, err = json.Marshal(&msg)
			if err != nil {
				glog.Errorf("failed to marshal ls_node message with error: %+v", err)
				return
			}
			if err := p.publisher.PublishMessage(bmp.LSNodeMsg, []byte(msg.RouterHash), j); err != nil {
				glog.Errorf("failed to push LSNode message to kafka with error: %+v", err)
				return
			}
			glog.V(6).Infof("ls_node message: %s", string(j))
		case 33:
			glog.V(6).Infof("Link NLRI")
			msg, err := p.lsLink("add", msg.PeerHeader, routeMonitorMsg.Update)
			if err != nil {
				glog.Errorf("failed to produce ls_link message with error: %+v", err)
				return
			}
			j, err = json.Marshal(&msg)
			if err != nil {
				glog.Errorf("failed to marshal ls_link message with error: %+v", err)
				return
			}
			if err := p.publisher.PublishMessage(bmp.LSLinkMsg, []byte(msg.RouterHash), j); err != nil {
				glog.Errorf("failed to push LSLink message to kafka with error: %+v", err)
				return
			}
			glog.V(6).Infof("ls_link message: %s", string(j))
		case 34:
			ipv4Flag = true
			glog.V(6).Infof("IPv4 Prefix NLRI")
			fallthrough
		case 35:
			if !ipv4Flag {
				glog.V(6).Infof("IPv6 Prefix NLRI")
			}
			msg, err := p.lsPrefix("add", msg.PeerHeader, routeMonitorMsg.Update, ipv4Flag)
			if err != nil {
				glog.Errorf("failed to produce ls_prefix message with error: %+v", err)
				return
			}
			j, err = json.Marshal(&msg)
			if err != nil {
				glog.Errorf("failed to marshal ls_prefix message with error: %+v", err)
				return
			}
			if err := p.publisher.PublishMessage(bmp.LSPrefixMsg, []byte(msg.RouterHash), j); err != nil {
				glog.Errorf("failed to push LSPrefix message to kafka with error: %+v", err)
				return
			}
			glog.V(6).Infof("ls_prefix message: %s", string(j))
		case 36:
			glog.Infof("SRv6 SID NLRI")
			msg, err := p.lsSRv6SID("add", msg.PeerHeader, routeMonitorMsg.Update)
			if err != nil {
				glog.Errorf("failed to produce ls_srv6_sid message with error: %+v", err)
				return
			}
			j, err = json.Marshal(&msg)
			if err != nil {
				glog.Errorf("failed to marshal ls_srv6_sid message with error: %+v", err)
				return
			}
			if err := p.publisher.PublishMessage(bmp.LSSRv6SIDMsg, []byte(msg.RouterHash), j); err != nil {
				glog.Errorf("failed to push LSSRv6SID message to kafka with error: %+v", err)
				return
			}
			glog.V(6).Infof("ls_srv6_sid message: %s", string(j))
		}
	case 15:
		// MP_UNREACH_NLRI
	default:
		// Original BGP's NLRI messages processing
		msgs := make([]UnicastPrefix, 0)
		if routeMonitorMsg.Update.WithdrawnRoutesLength != 0 {
			msg, err := p.nlri(DelPrefix, msg.PeerHeader, routeMonitorMsg.Update)
			if err != nil {
				glog.Errorf("failed to produce original NLRI Withdraw message with error: %+v", err)
				return
			}
			msgs = append(msgs, msg...)
		}
		msg, err := p.nlri(AddPrefix, msg.PeerHeader, routeMonitorMsg.Update)
		if err != nil {
			glog.Errorf("failed to produce original NLRI Withdraw message with error: %+v", err)
			return
		}
		msgs = append(msgs, msg...)
		// Loop through and publish all collected messages
		for _, m := range msgs {
			j, err := json.Marshal(&m)
			if err != nil {
				glog.Errorf("failed to marshal Unicast Prefix message with error: %+v", err)
				return
			}
			if err := p.publisher.PublishMessage(bmp.UnicastPrefixMsg, []byte(m.RouterHash), j); err != nil {
				glog.Errorf("failed to push Unicast Prefix message to kafka with error: %+v", err)
				return
			}
			glog.V(6).Infof("unicast_prefix message: %s", string(j))
		}
	}
}

func getNLRIMessageType(pattrs []bgp.PathAttribute) (int, error) {
	nlri, err := bgp.UnmarshalMPReachNLRI(pattrs[0].Attribute)
	if err != nil {
		return 0, err
	}

	switch {
	// 16388 BGP-LS	[RFC7752] : 71	BGP-LS	[RFC7752]
	case nlri.AddressFamilyID == 16388 && nlri.SubAddressFamilyID == 71:
		// Looking further down to get type of LS NLRI
		nlri71, err := ls.UnmarshalLSNLRI71(nlri.NLRI)
		if err != nil {
			return 0, err
		}
		switch nlri71.Type {
		case 1:
			// Node NLRI
			return 32, nil
		case 2:
			// Link NLRI
			return 33, nil
		case 3:
			// IPv4 Topology Prefix NLRI
			return 34, nil
		case 4:
			// IPv6 Topology Prefix NLRI
			return 35, nil
		case 6:
			// SRv6 SID NLRI
			return 36, nil
		default:
			return 0, fmt.Errorf("invalid LS NLRI type %d", nlri71.Type)

		}
	// 1 IP (IP version 4) : 1 unicast forwarding
	case nlri.AddressFamilyID == 1 && nlri.SubAddressFamilyID == 1:
		return 1, nil
	// 2 IP6 (IP version 6) : 1 unicast forwarding
	case nlri.AddressFamilyID == 2 && nlri.SubAddressFamilyID == 1:
		return 2, nil
	// 1 IP (IP version 4) : 4 MPLS Labels
	case nlri.AddressFamilyID == 1 && nlri.SubAddressFamilyID == 4:
		return 16, nil
	// 2 IP (IP version 6) : 4 MPLS Labels
	case nlri.AddressFamilyID == 2 && nlri.SubAddressFamilyID == 4:
		return 17, nil
	// 1 IP (IP version 4) : 128 MPLS-labeled VPN address
	case nlri.AddressFamilyID == 1 && nlri.SubAddressFamilyID == 128:
		return 18, nil
	// 2 IP (IP version 6) : 128 MPLS-labeled VPN address
	case nlri.AddressFamilyID == 2 && nlri.SubAddressFamilyID == 128:
		return 19, nil
	}

	return 0, fmt.Errorf("unsupported nlri of type: afi %d safi %d", nlri.AddressFamilyID, nlri.SubAddressFamilyID)
}
