package kafkaproducer

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (k *kafkaProducer) produceRouteMonitorMessage(msg bmp.Message) {
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
	glog.Info("><SB> route monitor message carries:")
	var afi uint16
	var safi uint8
	for _, pa := range routeMonitorMsg.Update.PathAttributes {

		switch pa.AttributeType {
		case 14:
			mp, err := bgp.UnmarshalMPReachNLRI(pa.Attribute)
			if err != nil {
				glog.Errorf("failed to unmarshal MP_REACH_NLRI (14)")
				return
			}
			afi = mp.AddressFamilyID
			safi = mp.SubAddressFamilyID
		case 29:
			_, err := bgpls.UnmarshalBGPLSNLRI(pa.Attribute)
			if err != nil {
				glog.Errorf("failed to unmarshal BGP-LS NLRI (29)")
				return
			}

		case 15:

		case 1:

		case 2:

		case 5:

		default:

		}

		glog.Infof("- attribute type: %d afi: %d safi: %d", pa.AttributeType, afi, safi)
		afi = 0
		safi = 0
	}
}
