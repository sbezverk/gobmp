package message

import (
	"crypto/md5"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
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
	switch routeMonitorMsg.Update.PathAttributes[0].AttributeType {
	case 14:
		// MP_REACH_NLRI
		// https://tools.ietf.org/html/rfc7752
		_, err := nlri14(p.speaker, msg.PeerHeader, routeMonitorMsg.Update)
		if err != nil {
			glog.Errorf("failed to produce MP_REACH_NLRI (14) message with error: %+v", err)
			return
		}
	case 15:
		// MP_UNREACH_NLRI
		// https://tools.ietf.org/html/rfc7752
		_, err := nlri15(p.speaker, msg.PeerHeader, routeMonitorMsg.Update)
		if err != nil {
			glog.Errorf("failed to produce MP_UNREACH_NLRI (15) message with error: %+v", err)
			return
		}
	default:
		// Original BGP's NLRI messages processing
		msgs := make([]UnicastPrefix, 0)
		if routeMonitorMsg.Update.WithdrawnRoutesLength != 0 {
			msg, err := nlriWd(p.speaker, msg.PeerHeader, routeMonitorMsg.Update)
			if err != nil {
				glog.Errorf("failed to produce original NLRI Withdraw message with error: %+v", err)
				return
			}
			msgs = append(msgs, msg...)
		}
		msg, err := nlriAdv(p.speaker, msg.PeerHeader, routeMonitorMsg.Update)
		if err != nil {
			glog.Errorf("failed to produce original NLRI Withdraw message with error: %+v", err)
			return
		}
		msgs = append(msgs, msg...)
		// Loop through and publish all collected messages
		// for _, m := range msgs {
		//	if err := p.publisher.PublishMessage(bmp.PeerDownMsg, []byte(m.RouterHash), j); err != nil {
		//	glog.Errorf("failed to push PeerDown message to kafka with error: %+v", err)
		//	return
		//}
		// }
	}
	// Remove after debugging
	logPathAttrType(routeMonitorMsg)
}

func nlri14(speaker string, ph *bmp.PerPeerHeader, update *bgp.Update) ([]byte, error) {
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
	glog.Infof("nlri14 processing requested..")
	return nil, nil
}

func nlri15(speaker string, ph *bmp.PerPeerHeader, update *bgp.Update) ([]byte, error) {
	glog.Infof("nlri15 processing requested..")
	return nil, nil
}

func nlriAdv(speaker string, ph *bmp.PerPeerHeader, update *bgp.Update) ([]UnicastPrefix, error) {
	glog.Infof("original nlri processing requested..")
	prfxs := make([]UnicastPrefix, 0)
	for _, p := range update.NLRI {
		glog.Infof("prefix: %+v length in bits: %d", p.Prefix, p.Length)

		prfx := UnicastPrefix{
			Action:       "add",
			RouterHash:   fmt.Sprintf("%s", md5.Sum([]byte(speaker))),
			RouterIP:     speaker,
			BaseAttrHash: update.GetBaseAttrHash(),
			PeerHash:     ph.GetPeerHash(),
			PeerASN:      ph.PeerAS,
			Timestamp:    ph.PeerTimestamp,
		}
		if ph.FlagV {
			prfx.IsIPv4 = false
			prfx.PeerIP = net.IP(ph.PeerAddress).To16().String()
		} else {
			prfx.IsIPv4 = true
			prfx.PeerIP = net.IP(ph.PeerAddress[12:]).To4().String()
		}
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}

func nlriWd(speaker string, ph *bmp.PerPeerHeader, update *bgp.Update) ([]UnicastPrefix, error) {
	glog.Infof("original nlri withdraw processing requested..")
	prfxs := make([]UnicastPrefix, 0)
	for _, p := range update.NLRI {
		glog.Infof("prefix: %+v length in bits: %d", p.Prefix, p.Length)
		prfx := UnicastPrefix{
			Action: "del",
		}

		prfxs = append(prfxs, prfx)
	}

	return nil, nil
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
