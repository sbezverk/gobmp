package message

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/internal"
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
	//	for _, pa := range routeMonitorMsg.Update.PathAttributes {
	switch routeMonitorMsg.Update.PathAttributes[0].AttributeType {
	case 14:
		// MP_REACH_NLRI
		// https://tools.ietf.org/html/rfc7752
		_, err := nlri14(routeMonitorMsg.Update)
		if err != nil {
			glog.Errorf("failed to produce MP_REACH_NLRI (14) route monitor message with error: %+v", err)
			return
		}
	case 15:
		// MP_UNREACH_NLRI
		// https://tools.ietf.org/html/rfc7752
		_, err := nlri15(routeMonitorMsg.Update)
		if err != nil {
			glog.Errorf("failed to produce MP_UNREACH_NLRI (15) route monitor message with error: %+v", err)
			return
		}
	default:
		glog.Warningf("Original NLRI: %+v", internal.MessageHex(routeMonitorMsg.Update.NLRI))
	}

	glog.Info("><SB> route monitor message carries attribute types:")
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

func nlri14(update *bgp.Update) ([]byte, error) {
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

func nlri15(update *bgp.Update) ([]byte, error) {
	glog.Infof("nlri15 processing requested..")
	return nil, nil
}
