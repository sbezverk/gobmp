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
	if routeMonitorMsg.Update == nil {
		return
	}
	attrType := uint8(0)
	index := 0
	if len(routeMonitorMsg.Update.PathAttributes) != 0 {
		// If PathAttribute is present in Update, then take the value of Attribute Type
		attrType, index = routeMonitorMsg.Update.GetNLRIType()
	}
	// Using first attribute type to select which nlri processor to call
	switch attrType {
	case 14:
		nlri, err := bgp.UnmarshalMPReachNLRI(routeMonitorMsg.Update.PathAttributes[index].Attribute, routeMonitorMsg.Update.HasPrefixSID(), p.addPathCapable)
		if err != nil {
			glog.Errorf("failed to process MP_REACH_NLRI with error: %+v", err)
		}
		p.processMPUpdate(nlri, AddPrefix, msg.PeerHeader, routeMonitorMsg.Update)
	case 15:
		// MP_UNREACH_NLRI
		nlri, err := bgp.UnmarshalMPUnReachNLRI(routeMonitorMsg.Update.PathAttributes[index].Attribute, p.addPathCapable)
		if err != nil {
			glog.Errorf("failed to process MP_UNREACH_NLRI with error: %+v", err)
		}
		p.processMPUpdate(nlri, DelPrefix, msg.PeerHeader, routeMonitorMsg.Update)
	default:
		t := bmp.UnicastPrefixMsg
		if p.splitAF {
			t = bmp.UnicastPrefixV4Msg
		}
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
			if err := p.marshalAndPublish(&m, t, []byte(m.RouterHash), false); err != nil {
				glog.Errorf("failed to process Unicast Prefix message with error: %+v", err)
				return
			}
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
