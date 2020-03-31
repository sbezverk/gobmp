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
		// https://tools.ietf.org/html/rfc7752
		t, err := getNLRIMessageType(routeMonitorMsg.Update.PathAttributes)
		if err != nil {
			glog.Errorf("failed to identify exact NLRI type with error: %+v", err)
			return
		}
		switch t {
		default:
		}
		// _, err := p.nlri14(msg.PeerHeader, routeMonitorMsg.Update)
		// if err != nil {
		// 	glog.Errorf("failed to produce MP_REACH_NLRI (14) message with error: %+v", err)
		// 	return
		// }
	case 15:
		// MP_UNREACH_NLRI
		// https://tools.ietf.org/html/rfc7752
		_, err := p.nlri15(msg.PeerHeader, routeMonitorMsg.Update)
		if err != nil {
			glog.Errorf("failed to produce MP_UNREACH_NLRI (15) message with error: %+v", err)
			return
		}
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

func (p *producer) nlri14(ph *bmp.PerPeerHeader, update *bgp.Update) ([]byte, error) {

	return nil, nil
}

// case 29:
// 	// BGP-LS NLRI
// 	// https://tools.ietf.org/html/rfc7752
// 	_, err := bgpls.UnmarshalBGPLSNLRI(pa.Attribute)
// 	if err != nil {
// 		glog.Errorf("failed to unmarshal BGP-LS NLRI (29)")
// 		return
// 	}
// case 40:
// 	// BGP Prefix-SID
// 	// https://tools.ietf.org/html/rfc8669
// glog.Infof("nlri14 processing requested..")

func (p *producer) nlri15(ph *bmp.PerPeerHeader, update *bgp.Update) ([]byte, error) {
	// glog.Infof("nlri15 processing requested..")
	return nil, nil
}

func getNLRIMessageType(pattrs []bgp.PathAttribute) (int, error) {
	nlri, err := bgp.UnmarshalMPReachNLRI(pattrs[0].Attribute)
	if err != nil {
		return 0, err
	}
	glog.Infof("><SB> : afi %d safi %d :", nlri.AddressFamilyID, nlri.SubAddressFamilyID)

	return 0, nil
}

func logPathAttrType(routeMonitorMsg *bmp.RouteMonitor) {
	glog.Info("route monitor message carries attribute types:")
	var s string
	for i, pa := range routeMonitorMsg.Update.PathAttributes {
		s += fmt.Sprintf("type: %d", pa.AttributeType)
		switch pa.AttributeType {
		case 14:
			// MP_REACH_NLRI
			// https://tools.ietf.org/html/rfc7752
			mp, err := bgp.UnmarshalMPReachNLRI(pa.Attribute)
			if err != nil {
				glog.Errorf("failed to unmarshal MP_REACH_NLRI (14)")
				return
			}
			s += fmt.Sprintf(" : afi %d safi %d :", mp.AddressFamilyID, mp.SubAddressFamilyID)
		case 15:
			// MP_UNREACH_NLRI
			// https://tools.ietf.org/html/rfc7752
			mp, err := bgp.UnmarshalMPUnReachNLRI(pa.Attribute)
			if err != nil {
				glog.Errorf("failed to unmarshal MP_UNREACH_NLRI (15)")
				return
			}
			s += fmt.Sprintf(" : afi %d safi %d :", mp.AddressFamilyID, mp.SubAddressFamilyID)
		}
		if i < len(routeMonitorMsg.Update.PathAttributes)-1 {
			s += ", "
		}
	}
	glog.Infof("- %s", s)
}
