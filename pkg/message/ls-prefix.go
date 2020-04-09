package message

import (
	"net"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsPrefix(operation string, ph *bmp.PerPeerHeader, update *bgp.Update) (*LSPrefix, error) {
	nlri14, err := update.GetNLRI14()
	if err != nil {
		return nil, err
	}
	nlri71, err := nlri14.GetNLRI71()
	if err != nil {
		return nil, err
	}
	msg := LSPrefix{
		Action:       operation,
		RouterHash:   p.speakerHash,
		RouterIP:     p.speakerIP,
		BaseAttrHash: update.GetBaseAttrHash(),
		PeerHash:     ph.GetPeerHash(),
		PeerASN:      ph.PeerAS,
		Timestamp:    ph.PeerTimestamp,
	}
	msg.Nexthop = nlri14.GetNextHop()
	msg.PeerIP = ph.GetPeerAddrString()
	// Processing other nlri and attributes, since they are optional, processing only if they exist
	prfx, err := nlri71.GetPrefixNLRI()
	if err == nil {
		msg.Protocol = prfx.GetPrefixProtocolID()
		msg.LSID = prfx.GetPrefixLSID()
		msg.OSPFAreaID = prfx.GetPrefixOSPFAreaID()
		msg.LocalNodeHash = prfx.LocalNodeHash
		msg.IGPRouterID = prfx.GetLocalIGPRouterID()
		msg.IGPMetric = prfx.Prefix.GetPrefixMetric()
		route := prfx.Prefix.GetPrefixIPReachability()
		msg.PrefixLen = int32(route.Length)
		if ph.FlagV {
			msg.Prefix = net.IP(prfx.Prefix.GetPrefixIPReachability().Prefix).To16().String()
		} else {
			msg.Prefix = net.IP(prfx.Prefix.GetPrefixIPReachability().Prefix).To4().String()
		}
	}
	lsprefix, err := update.GetNLRI29()
	if err == nil {
		if ph.FlagV {
			msg.RouterID = lsprefix.GetLocalIPv6RouterID()
		} else {
			msg.RouterID = lsprefix.GetLocalIPv4RouterID()
		}
		msg.MTID = lsprefix.GetMTID()
		msg.ISISAreaID = lsprefix.GetISISAreaID()
		msg.IGPMetric = lsprefix.GetIGPMetric()
		if ps, err := lsprefix.GetLSPrefixSID(); err == nil {
			msg.LSPrefixSID = ps
		}
	}
	msg.ASPath = update.GetAttrASPath(p.as4Capable)
	if med := update.GetAttrMED(); med != nil {
		msg.MED = *med
	}
	if lp := update.GetAttrLocalPref(); lp != nil {
		msg.LocalPref = *lp
	}

	return &msg, nil
}
