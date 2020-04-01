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
			glog.Infof("1 IP (IP version 4) : 128 MPLS-labeled VPN address")
		case 19:
			glog.Infof("2 IP (IP version 6) : 128 MPLS-labeled VPN address")
		case 32:
			glog.Infof("Node NLRI")
			p.lsNode(msg.PeerHeader, routeMonitorMsg.Update)
		case 33:
			glog.Infof("Link NLRI")
		case 34:
			glog.Infof("IPv4 Topology Prefix NLRI")
		case 35:
			glog.Infof("IPv6 Topology Prefix NLRI")
		case 36:
			glog.Infof("SRv6 SID NLRI")
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
		}
	}
}

func (p *producer) lsNode(ph *bmp.PerPeerHeader, update *bgp.Update) (*LSNode, error) {
	nlri14, err := update.GetNLRI14()
	if err != nil {
		return nil, err
	}
	nlri71, err := nlri14.GetNLRI71()
	if err != nil {
		return nil, err
	}
	msg := LSNode{
		Action:       "add",
		RouterHash:   p.speakerHash,
		RouterIP:     p.speakerIP,
		BaseAttrHash: update.GetBaseAttrHash(),
		PeerHash:     ph.GetPeerHash(),
		PeerASN:      ph.PeerAS,
		Timestamp:    ph.PeerTimestamp,
	}
	msg.Nexthop = nlri14.GetNextHop()
	// Processing other nlri and attributes, since they are optional, processing only if they exist
	node, err := nlri71.GetNodeNLRI()
	if err == nil {
		msg.Protocol = node.GetProtocolID()
		msg.IGPRouterID = node.GetIdentifier()
	}

	lsnode, err := update.GetNLRI29()
	if err == nil {
		glog.Infof("><SB> LS Node: \n%s", lsnode.String())
	}

	if count, path := update.GetAttrASPathString(p.as4Capable); count != 0 {
		msg.ASPath = path
	}
	if med := update.GetAttrMED(); med != nil {
		msg.MED = *med
	}
	glog.V(6).Infof("LS Node messages: %+v", msg)

	return &msg, nil
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
