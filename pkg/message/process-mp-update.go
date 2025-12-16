package message

import (
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

// extractColorEC extracts Color Extended Community from BaseAttributes per RFC 9723.
// RFC 9723 defines BGP Colored Prefix Routing (CPR) for SRv6, which uses the Color
// Extended Community (Type 0x0b, RFC 5512) to associate intent-aware routing colors
// with IPv6 (and IPv4) Unicast prefixes. Returns nil if no Color EC is present.
func extractColorEC(attrs *bgp.BaseAttributes) *uint32 {
	if attrs == nil || attrs.ExtCommunityList == nil {
		return nil
	}
	for _, ec := range attrs.ExtCommunityList {
		if strings.HasPrefix(ec, bgp.ECPColor) {
			// Parse color value (format: "color=12345")
			if val, err := strconv.ParseUint(ec[len(bgp.ECPColor):], 10, 32); err == nil {
				color := uint32(val)
				return &color
			}
		}
	}
	return nil
}

func (p *producer) processMPUpdate(nlri bgp.MPNLRI, operation int, ph *bmp.PerPeerHeader, update *bgp.Update) {
	labeled := false
	labeledSet := false
	switch nlri.GetAFISAFIType() {
	case 1:
		// MP_REACH_NLRI AFI 1 SAFI 1
		if !labeledSet {
			labeledSet = true
			labeled = false
		}
		fallthrough
	case 2:
		// MP_REACH_NLRI AFI 2 SAFI 1
		if !labeledSet {
			labeledSet = true
			labeled = false
		}
		fallthrough
	case 16:
		// MP_REACH_NLRI AFI 1 SAFI 4
		if !labeledSet {
			labeledSet = true
			labeled = true
		}
		fallthrough
	case 17:
		// MP_REACH_NLRI AFI 2 SAFI 4
		if !labeledSet {
			labeled = true
		}
		msgs, err := p.unicast(nlri, operation, ph, update, labeled)
		if err != nil {
			return
		}
		// Loop through and publish all collected messages
		for _, m := range msgs {
			// Extract Color EC for RFC 9723 CPR
			m.Color = extractColorEC(update.BaseAttributes)

			topicType := bmp.UnicastPrefixMsg
			if p.splitAF {
				if m.IsIPv4 {
					topicType = bmp.UnicastPrefixV4Msg
				} else {
					topicType = bmp.UnicastPrefixV6Msg
				}
			}
			if err := p.marshalAndPublish(&m, topicType, []byte(m.RouterHash), false); err != nil {
				glog.Errorf("failed to process Unicast Prefix message with error: %+v", err)
				return
			}
		}
	case 18:
		fallthrough
	case 19:
		// Updatng the error handling in the l3vpn case...
		msgs, err := p.l3vpn(nlri, operation, ph, update)
		if err != nil {
			// Only log as error if its not the common "not found" case
			if err.Error() == "not found" || err.Error() == "NLRI length is 0" {
				if glog.V(6) {
					glog.Infof("No L3VPN NLRI found in update") // Debug level logging
				}
			} else {
				glog.Errorf("failed to produce l3vpn messages with error: %+v", err)
			}
			return
		}
		for _, m := range msgs {
			topicType := bmp.L3VPNMsg
			if p.splitAF {
				if m.IsIPv4 {
					topicType = bmp.L3VPNV4Msg
				} else {
					topicType = bmp.L3VPNV6Msg
				}
			}
			if err := p.marshalAndPublish(&m, topicType, []byte(m.RouterHash), false); err != nil {
				glog.Errorf("failed to process L3VPN message with error: %+v", err)
				return
			}
		}
	case 24:
		msgs, err := p.evpn(nlri, operation, ph, update)
		if err != nil {
			glog.Errorf("failed to produce evpn messages with error: %+v", err)
			return
		}
		for _, msg := range msgs {
			if err := p.marshalAndPublish(&msg, bmp.EVPNMsg, []byte(msg.RouterHash), false); err != nil {
				glog.Errorf("failed to process EVPNP message with error: %+v", err)
				return
			}
		}
	case 25:
		fallthrough
	case 26:
		msgs, err := p.srpolicy(nlri, operation, ph, update)
		if err != nil {
			glog.Errorf("failed to produce srpolicy messages with error: %+v", err)
			return
		}
		for _, m := range msgs {
			topicType := bmp.SRPolicyMsg
			if p.splitAF {
				if m.IsIPv4 {
					topicType = bmp.SRPolicyV4Msg
				} else {
					topicType = bmp.SRPolicyV6Msg
				}
			}
			if err := p.marshalAndPublish(&m, topicType, []byte(m.RouterHash), false); err != nil {
				glog.Errorf("failed to process SRPolicy message with error: %+v", err)
				return
			}
		}
	case 27:
		msgs, err := p.flowspec(nlri, operation, ph, update)
		if err != nil {
			glog.Errorf("failed to produce flowspec messages with error: %+v", err)
			return
		}
		for _, m := range msgs {
			topicType := bmp.FlowspecMsg
			if p.splitAF {
				if m.IsIPv4 {
					topicType = bmp.FlowspecV4Msg
				} else {
					topicType = bmp.FlowspecV6Msg
				}
			}
			if err := p.marshalAndPublish(&m, topicType, []byte(m.SpecHash), false); err != nil {
				glog.Errorf("failed to process Flowspec message with error: %+v", err)
				return
			}
		}
	case 28:
		fallthrough
	case 29:
		msgs, err := p.multicast(nlri, operation, ph, update)
		if err != nil {
			glog.Errorf("failed to produce multicast messages with error: %+v", err)
			return
		}
		for _, m := range msgs {
			topicType := bmp.MulticastV4Msg
			if m.IsIPv4 {
				topicType = bmp.MulticastV4Msg
			} else {
				topicType = bmp.MulticastV6Msg
			}
			if err := p.marshalAndPublish(&m, topicType, []byte(m.RouterHash), false); err != nil {
				glog.Errorf("failed to process Multicast message with error: %+v", err)
				return
			}
		}
	case 32:
		fallthrough
	case 33:
		msgs, err := p.mcastvpn(nlri, operation, ph, update)
		if err != nil {
			glog.Errorf("failed to produce mcastvpn messages with error: %+v", err)
			return
		}
		for _, m := range msgs {
			topicType := bmp.MCASTVPNV6Msg
			if m.IsIPv4 {
				topicType = bmp.MCASTVPNV4Msg
			}
			if err := p.marshalAndPublish(&m, topicType, []byte(m.RouterHash), false); err != nil {
				glog.Errorf("failed to process MCAST-VPN message with error: %+v", err)
				return
			}
		}
	case 71:
		p.processNLRI71SubTypes(nlri, operation, ph, update)
	}
}

func (p *producer) processNLRI71SubTypes(nlri bgp.MPNLRI, operation int, ph *bmp.PerPeerHeader, update *bgp.Update) {
	// NLRI 71 carries 6 known sub type
	ls, err := nlri.GetNLRI71()
	if err != nil {
		glog.Errorf("failed to NLRI 71 with error: %+v", err)
		return
	}
	for _, e := range ls.NLRI {
		// ipv4Flag used to differentiate between IPv4 and IPv6 Prefix NLRI messages
		ipv4Flag := false
		switch e.Type {
		case 1:
			n, ok := e.LS.(*base.NodeNLRI)
			if !ok {
				glog.Errorf("failed to produce ls_node message with error: %+v", err)
				continue
			}
			msg, err := p.lsNode(n, nlri.GetNextHop(), operation, ph, update, ph.IsRemotePeerIPv6())
			if err != nil {
				glog.Errorf("failed to produce ls_node message with error: %+v", err)
				continue
			}
			if err := p.marshalAndPublish(&msg, bmp.LSNodeMsg, []byte(msg.RouterHash), false); err != nil {
				glog.Errorf("failed to process LSNode message with error: %+v", err)
				continue
			}
		case 2:
			l, ok := e.LS.(*base.LinkNLRI)
			if !ok {
				glog.Errorf("failed to produce ls_link message with error: %+v", err)
				continue
			}
			msg, err := p.lsLink(l, nlri.GetNextHop(), operation, ph, update, ph.IsRemotePeerIPv6())
			if err != nil {
				glog.Errorf("failed to produce ls_link message with error: %+v", err)
				continue
			}
			if err := p.marshalAndPublish(&msg, bmp.LSLinkMsg, []byte(msg.RouterHash), false); err != nil {
				glog.Errorf("failed to process LSLink message with error: %+v", err)
				continue
			}
		case 3:
			ipv4Flag = true
			fallthrough
		case 4:
			prfx, ok := e.LS.(*base.PrefixNLRI)
			if !ok {
				glog.Errorf("failed to produce ls_prefix message with error: %+v", err)
				continue
			}
			msg, err := p.lsPrefix(prfx, nlri.GetNextHop(), operation, ph, update, ipv4Flag)
			if err != nil {
				glog.Errorf("failed to produce ls_prefix message with error: %+v", err)
				continue
			}
			if err := p.marshalAndPublish(&msg, bmp.LSPrefixMsg, []byte(msg.RouterHash), false); err != nil {
				glog.Errorf("failed to process LSPrefix message with error: %+v", err)
				continue
			}
		case 6:
			s, ok := e.LS.(*srv6.SIDNLRI)
			if !ok {
				glog.Errorf("failed to produce ls_srv6_sid message with error: %+v", err)
				continue
			}
			msg, err := p.lsSRv6SID(s, nlri.GetNextHop(), operation, ph, update)
			if err != nil {
				glog.Errorf("failed to produce ls_srv6_sid message with error: %+v", err)
				continue
			}
			if err := p.marshalAndPublish(&msg, bmp.LSSRv6SIDMsg, []byte(msg.RouterHash), false); err != nil {
				glog.Errorf("failed to process LSSRv6SID message with error: %+v", err)
				continue
			}
		default:
			glog.Warningf("Unknown NLRI 71 Sub type %d", e.Type)
		}

	}
}
