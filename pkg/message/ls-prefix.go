package message

import (
	"net"

	"github.com/golang/glog"
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
	if ph.FlagV {
		// IPv6 specific conversions
		msg.PeerIP = net.IP(ph.PeerAddress).To16().String()
	} else {
		// IPv4 specific conversions
		msg.PeerIP = net.IP(ph.PeerAddress[12:]).To4().String()
	}
	// Processing other nlri and attributes, since they are optional, processing only if they exist
	nlri71.GetLinkNLRI()
	prefix, err := nlri71.GetPrefixNLRI()
	if err == nil {
		msg.Protocol = prefix.GetPrefixProtocolID()
		msg.LSID = prefix.GetPrefixLSID()
		msg.OSPFAreaID = prefix.GetPrefixOSPFAreaID()
		if ph.FlagV {
		} else {
		}
		msg.LocalNodeHash = prefix.LocalNodeHash
		msg.IGPRouterID = prefix.GetLocalIGPRouterID()
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
	}
	msg.ASPath = update.GetAttrASPath(p.as4Capable)
	if med := update.GetAttrMED(); med != nil {
		msg.MED = *med
	}
	if lp := update.GetAttrLocalPref(); lp != nil {
		msg.LocalPref = *lp
	}

	glog.Infof("lsPrefix message: %+v", msg)

	return &msg, nil
}
