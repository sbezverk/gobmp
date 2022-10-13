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
		PeerType:   uint8(ph.PeerType),
		PeerHash:   ph.GetPeerHash(),
		PeerASN:    ph.PeerAS,
		Timestamp:  ph.GetPeerTimestamp(),
		DomainID:   prfx.GetIdentifier(),
	}
	if f, err := ph.IsAdjRIBInPost(); err == nil {
		msg.IsAdjRIBInPost = f
	}
	if f, err := ph.IsAdjRIBOutPost(); err == nil {
		msg.IsAdjRIBOutPost = f
	}
	if f, err := ph.IsLocRIBFiltered(); err == nil {
		msg.IsLocRIBFiltered = f
	}
	msg.Nexthop = nextHop
	msg.PeerIP = ph.GetPeerAddrString()
	msg.ProtocolID = prfx.ProtocolID
	msg.Protocol = prfx.GetPrefixProtocolID()
	msg.LSID = prfx.GetPrefixLSID()
	msg.LocalNodeHash = prfx.LocalNodeHash
	msg.IGPRouterID = prfx.GetLocalIGPRouterID()
	msg.MTID = prfx.Prefix.GetPrefixMTID()
	route := prfx.Prefix.GetPrefixIPReachability(ipv4)
	msg.PrefixLen = int32(route.Length)
	pr := prfx.Prefix.GetPrefixIPReachability(ipv4).Prefix
	if !ipv4 {
		msg.Prefix = net.IP(pr).To16().String()
	} else {
		msg.Prefix = net.IP(pr).To4().String()
	}
	switch prfx.ProtocolID {
	case base.ISISL1:
		fallthrough
	case base.ISISL2:
		// Proposed by Peter Psenak <ppsenak@cisco.com>
		// 1027 TLV is not sent for ISIS links/prefixes, because ISIS has no
		// concept of areas. The proposal is to use generic representation,
		// so include area-id and always set to 0 for ISIS.
		msg.AreaID = "0"
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		msg.OSPFRouteType = prfx.Prefix.GetPrefixOSPFRouteType()
		msg.AreaID = prfx.LocalNode.GetOSPFAreaID()
	default:
		msg.AreaID = "0"
	}
	lsprefix, err := update.GetNLRI29()
	if err == nil {
		if !ipv4 {
			msg.RouterID = lsprefix.GetLocalIPv6RouterID()
		} else {
			msg.RouterID = lsprefix.GetLocalIPv4RouterID()
		}
		msg.PrefixMetric = lsprefix.GetPrefixMetric()
		msg.IGPRouteTag = lsprefix.GetPrefixIGPRouteTag()
		if f, err := lsprefix.GetPrefixIGPFlags(); err == nil {
			msg.IGPFlags = f
		}
		msg.IGPExtRouteTag = lsprefix.GetPrefixIGPExtRouteTag()
		if s, err := lsprefix.GetPrefixAttrTLVs(prfx.ProtocolID); err == nil {
			msg.PrefixAttrTLVs = s
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
