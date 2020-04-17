package message

import (
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
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
	// Using first attribute type to select which nlri processor to call
	switch routeMonitorMsg.Update.PathAttributes[0].AttributeType {
	case 14:
		glog.Infof("MP_REAH_NLRI")
		// New approach
		// 1. Instantiate MP REACH NLRI, it returns MPNLRI Interface
		// 2. AFI/SAFI will be identified inside of ProcessMPUpdate by calling interface function Get
		// MP_REACH_NLRI

		//		t, err := getNLRIMessageType(routeMonitorMsg.Update.PathAttributes)
		//		if err != nil {
		//			glog.Errorf("failed to identify exact NLRI type with error: %+v", err)
		//			return
		//
		//		}
		nlri, err := bgp.UnmarshalMPReachNLRI(routeMonitorMsg.Update.PathAttributes[0].Attribute)
		if err != nil {
			glog.Errorf("failed to process MP_REACH_NLRI with error: %+v", err)
		}
		p.processMPUpdate(nlri, AddPrefix, msg.PeerHeader, routeMonitorMsg.Update)
	case 15:
		// MP_UNREACH_NLRI
		glog.Infof("MP_UNREAH_NLRI")
		//		_, err := p.mpUnreach(msg.PeerHeader, routeMonitorMsg.Update)
		//		if err != nil {
		//			glog.Errorf("failed to produce  MP_UNREAH_NLRI messages with error: %+v", err)
		//			return
		//		}
		//		// Loop through and publish all collected messages
		//		for _, m := range msgs {
		//			if err := p.marshalAndPublish(&m, bmp.UnicastPrefixMsg, []byte(m.RouterHash), true); err != nil {
		//				glog.Errorf("failed to process Unicast Prefix message with error: %+v", err)
		//				return
		//			}
		//		}
		nlri, err := bgp.UnmarshalMPReachNLRI(routeMonitorMsg.Update.PathAttributes[0].Attribute)
		if err != nil {
			glog.Errorf("failed to process MP_REACH_NLRI with error: %+v", err)
		}
		p.processMPUpdate(nlri, DelPrefix, msg.PeerHeader, routeMonitorMsg.Update)
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
			if err := p.marshalAndPublish(&m, bmp.UnicastPrefixMsg, []byte(m.RouterHash), false); err != nil {
				glog.Errorf("failed to process Unicast Prefix message with error: %+v", err)
				return
			}
			glog.V(6).Infof("unicast_prefix message: %s", string(j))
		}
	}
}

func (p *producer) marshalAndPublish(msg interface{}, msgType int, hash []byte, debug bool) error {
	j, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal a message of type %d with error: %+v", msgType, err)
	}
	if err := p.publisher.PublishMessage(msgType, hash, j); err != nil {
		return fmt.Errorf("failed to push a message of type %d to kafka with error: %+v", msgType, err)
	}
	if debug {
		glog.Infof("message of type: %+v json: %s", msgType, string(j))
	}
	return nil
}

// func getNLRIMessageType(pattrs []bgp.PathAttribute) (int, error) {
// 	nlri, err := bgp.UnmarshalMPReachNLRI(pattrs[0].Attribute)
// 	if err != nil {
// 		return 0, err
// 	}

// 	switch {
// 	// 16388 BGP-LS	[RFC7752] : 71	BGP-LS	[RFC7752]
// 	case nlri.AddressFamilyID == 16388 && nlri.SubAddressFamilyID == 71:
// 		// Looking further down to get type of LS NLRI
// 		nlri71, err := ls.UnmarshalLSNLRI71(nlri.NLRI)
// 		if err != nil {
// 			return 0, err
// 		}
// 		switch nlri71.Type {
// 		case 1:
// 			// Node NLRI
// 			return 32, nil
// 		case 2:
// 			// Link NLRI
// 			return 33, nil
// 		case 3:
// 			// IPv4 Topology Prefix NLRI
// 			return 34, nil
// 		case 4:
// 			// IPv6 Topology Prefix NLRI
// 			return 35, nil
// 		case 6:
// 			// SRv6 SID NLRI
// 			return 36, nil
// 		default:
// 			return 0, fmt.Errorf("invalid LS NLRI type %d", nlri71.Type)

// 		}
// 	// 1 IP (IP version 4) : 1 unicast forwarding
// 	case nlri.AddressFamilyID == 1 && nlri.SubAddressFamilyID == 1:
// 		return 1, nil
// 	// 2 IP6 (IP version 6) : 1 unicast forwarding
// 	case nlri.AddressFamilyID == 2 && nlri.SubAddressFamilyID == 1:
// 		return 2, nil
// 	// 1 IP (IP version 4) : 4 MPLS Labels
// 	case nlri.AddressFamilyID == 1 && nlri.SubAddressFamilyID == 4:
// 		return 16, nil
// 	// 2 IP (IP version 6) : 4 MPLS Labels
// 	case nlri.AddressFamilyID == 2 && nlri.SubAddressFamilyID == 4:
// 		return 17, nil
// 	// 1 IP (IP version 4) : 128 MPLS-labeled VPN address
// 	case nlri.AddressFamilyID == 1 && nlri.SubAddressFamilyID == 128:
// 		return 18, nil
// 	// 2 IP (IP version 6) : 128 MPLS-labeled VPN address
// 	case nlri.AddressFamilyID == 2 && nlri.SubAddressFamilyID == 128:
// 		return 19, nil
// 	// AFI of 25 (L2VPN) and a SAFI of 65 (VPLS)
// 	case nlri.AddressFamilyID == 25 && nlri.SubAddressFamilyID == 65:
// 		return 23, nil
// 	// AFI of 25 (L2VPN) and a SAFI of 70 (EVPN)
// 	case nlri.AddressFamilyID == 25 && nlri.SubAddressFamilyID == 70:
// 		return 24, nil
// 	}

// 	return 0, fmt.Errorf("unsupported nlri of type: afi %d safi %d", nlri.AddressFamilyID, nlri.SubAddressFamilyID)
// }
