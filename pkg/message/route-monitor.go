package message

import (
	"encoding/json"
	"fmt"
	"net"

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
	reachIndexes := make([]int, 0, 1)
	unreachIndexes := make([]int, 0, 1)
	for i, attr := range routeMonitorMsg.Update.PathAttributes {
		switch attr.AttributeType {
		case bgp.MP_REACH_NLRI:
			reachIndexes = append(reachIndexes, i)
		case bgp.MP_UNREACH_NLRI:
			unreachIndexes = append(unreachIndexes, i)
		}
	}
	for _, index := range reachIndexes {
		p.processMPReach(routeMonitorMsg.Update.PathAttributes[index].Attribute, msg.PeerHeader, routeMonitorMsg.Update)
	}
	for _, index := range unreachIndexes {
		p.processMPUnreach(routeMonitorMsg.Update.PathAttributes[index].Attribute, msg.PeerHeader, routeMonitorMsg.Update)
	}
	if (len(reachIndexes) == 0 && len(unreachIndexes) == 0) || routeMonitorMsg.Update.WithdrawnRoutesLength != 0 || len(routeMonitorMsg.Update.NLRI) != 0 {
		p.processBGP4Update(msg.PeerHeader, routeMonitorMsg.Update)
	}
}

func (p *producer) processMPReach(attribute []byte, ph *bmp.PerPeerHeader, update *bgp.Update) {
	nlri, err := bgp.UnmarshalMPReachNLRI(attribute, update.HasPrefixSID(), p.mpAddPathCapability(ph, attribute))
	if err != nil {
		glog.Errorf("failed to process MP_REACH_NLRI with error: %+v", err)
		return
	}
	reachableUpdate := copyUpdate(update)
	if reach, ok := nlri.(*bgp.MPReachNLRI); ok {
		validateNHC(reachableUpdate, reach.AddressFamilyID, reach.SubAddressFamilyID, reach.NextHopAddress, ph)
	}
	p.processMPUpdate(nlri, AddPrefix, ph, reachableUpdate)
}

func (p *producer) processMPUnreach(attribute []byte, ph *bmp.PerPeerHeader, update *bgp.Update) {
	nlri, err := bgp.UnmarshalMPUnReachNLRI(attribute, p.mpAddPathCapability(ph, attribute), update.HasPrefixSID())
	if err != nil {
		glog.Errorf("failed to process MP_UNREACH_NLRI with error: %+v", err)
		return
	}
	p.processMPUpdate(nlri, DelPrefix, ph, withoutNHC(update))
}

func copyUpdate(update *bgp.Update) *bgp.Update {
	if update == nil {
		return nil
	}
	copied := *update
	if update.BaseAttributes != nil {
		attributes := *update.BaseAttributes
		attributes.NHCAttr = append([]byte(nil), update.BaseAttributes.NHCAttr...)
		if update.BaseAttributes.NHC != nil {
			nhc := *update.BaseAttributes.NHC
			nhc.NextHop = append([]byte(nil), update.BaseAttributes.NHC.NextHop...)
			nhc.Characteristics = make([]bgp.NHCCharacteristic, len(update.BaseAttributes.NHC.Characteristics))
			for i, characteristic := range update.BaseAttributes.NHC.Characteristics {
				nhc.Characteristics[i] = characteristic
				nhc.Characteristics[i].Value = append([]byte(nil), characteristic.Value...)
			}
			if update.BaseAttributes.NHC.BGPID != nil {
				bgpID := *update.BaseAttributes.NHC.BGPID
				nhc.BGPID = &bgpID
			}
			attributes.NHC = &nhc
		}
		copied.BaseAttributes = &attributes
	}
	return &copied
}

func withoutNHC(update *bgp.Update) *bgp.Update {
	copied := copyUpdate(update)
	if copied == nil || copied.BaseAttributes == nil {
		return copied
	}
	copied.BaseAttributes.NHCAttr = nil
	copied.BaseAttributes.NHC = nil
	copied.BaseAttributes.NHCMalformed = false
	copied.BaseAttributes.NHCEmpty = false
	copied.BaseAttributes.NHCDiscarded = false
	copied.BaseAttributes.NHCUnverified = false
	return copied
}

func (p *producer) processBGP4Update(ph *bmp.PerPeerHeader, update *bgp.Update) {
	reachableUpdate := copyUpdate(update)
	var nextHop []byte
	if len(reachableUpdate.NLRI) != 0 && reachableUpdate.BaseAttributes != nil {
		nextHop = net.ParseIP(reachableUpdate.BaseAttributes.Nexthop).To4()
	}
	validateNHC(reachableUpdate, 1, 1, nextHop, ph)
	t := bmp.UnicastPrefixMsg
	if p.splitAF {
		t = bmp.UnicastPrefixV4Msg
	}
	msgs := make([]*UnicastPrefix, 0)
	if update.WithdrawnRoutesLength != 0 {
		msg, err := p.nlri(DelPrefix, ph, withoutNHC(update))
		if err != nil {
			glog.Errorf("failed to produce original NLRI Withdraw message with error: %+v", err)
			return
		}
		msgs = append(msgs, msg...)
	}
	msg, err := p.nlri(AddPrefix, ph, reachableUpdate)
	if err != nil {
		glog.Errorf("failed to produce original NLRI message with error: %+v", err)
		return
	}
	msgs = append(msgs, msg...)
	for _, m := range msgs {
		if err := p.marshalAndPublish(&m, t, []byte(m.RouterHash)); err != nil {
			glog.Errorf("failed to process Unicast Prefix message with error: %+v", err)
			return
		}
	}
}

func validateNHC(update *bgp.Update, afi uint16, safi uint8, nextHop []byte, ph *bmp.PerPeerHeader) {
	if update == nil || update.BaseAttributes == nil || update.BaseAttributes.NHC == nil {
		return
	}
	var peerBGPID net.IP
	var peerAS uint32
	authoritativePeer := false
	if ph != nil {
		if inbound, err := ph.IsAdjRIBIn(); err == nil && inbound {
			peerBGPID = net.IP(ph.PeerBGPID)
			peerAS = ph.PeerAS
			authoritativePeer = true
		}
	}
	nhc := update.BaseAttributes.NHC
	if nhc.SemanticallyMatchesNextHop(afi, safi, nextHop, peerBGPID, peerAS) {
		return
	}
	if !authoritativePeer && nhc.BGPID != nil && nhc.SemanticallyMatchesNextHop(afi, safi, nextHop, net.ParseIP(nhc.BGPID.Identifier), nhc.BGPID.AS) {
		update.BaseAttributes.NHCUnverified = true
		return
	}
	update.BaseAttributes.NHC = nil
	update.BaseAttributes.NHCDiscarded = true
	glog.Warningf("discarded NHC attribute whose embedded next hop did not semantically match AFI %d SAFI %d route next hop", afi, safi)
}

func (p *producer) marshalAndPublish(msg interface{}, msgType int, hash []byte) error {
	ensureMessageHash(msg)
	j, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal a message of type %d with error: %w", msgType, err)
	}
	if err := p.publisher.PublishMessage(msgType, hash, j); err != nil {
		return fmt.Errorf("failed to push a message of type %d to kafka with error: %w", msgType, err)
	}
	return nil
}
