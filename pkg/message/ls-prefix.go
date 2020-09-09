package message

import (
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsPrefix(prfx *base.PrefixNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update, ipv4 bool) (*LSPrefix, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}
	msg := LSPrefix{
		Action:     operation,
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
		PeerHash:   ph.GetPeerHash(),
		PeerASN:    ph.PeerAS,
		Timestamp:  ph.GetPeerTimestamp(),
	}
	msg.Nexthop = nextHop
	msg.PeerIP = ph.GetPeerAddrString()
	msg.ProtocolID = prfx.ProtocolID
	msg.Protocol = prfx.GetPrefixProtocolID()
	msg.LSID = prfx.GetPrefixLSID()
	msg.LocalNodeHash = prfx.LocalNodeHash
	msg.IGPRouterID = prfx.GetLocalIGPRouterID()
	msg.IGPMetric = prfx.Prefix.GetPrefixMetric()
	msg.IGPRouteTag = prfx.Prefix.GetPrefixIGPRouteTag()
	msg.IGPExtRouteTag = prfx.Prefix.GetPrefixIGPExtRouteTag()
	msg.MTID = prfx.Prefix.GetPrefixMTID()
	route := prfx.Prefix.GetPrefixIPReachability(ipv4)
	msg.PrefixLen = int32(route.Length)
	pr := prfx.Prefix.GetPrefixIPReachability(ipv4).Prefix
	if !ipv4 {
		msg.Prefix = net.IP(pr).To16().String()
	} else {
		msg.Prefix = net.IP(pr).To4().String()
	}
	lsprefix, err := update.GetNLRI29()
	if err == nil {
		if ph.FlagV {
			msg.RouterID = lsprefix.GetLocalIPv6RouterID()
		} else {
			msg.RouterID = lsprefix.GetLocalIPv4RouterID()
		}
		msg.IGPMetric = lsprefix.GetIGPMetric()
		if ps, err := lsprefix.GetLSPrefixSID(); err == nil {
			msg.LSPrefixSID = ps
		}
		if paf, err := lsprefix.GetLSPrefixAttrFlags(); err == nil {
			msg.PrefixAttrFlags = paf
		}
		if fap, err := lsprefix.GetFlexAlgoPrefixMetric(); err == nil {
			msg.FlexAlgoPrefixMetric = fap
		}
		if loc, err := lsprefix.GetLSSRv6Locator(); err == nil {
			msg.SRv6Locator = loc
		}
	}

	return &msg, nil
}
