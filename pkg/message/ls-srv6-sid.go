package message

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsSRv6SID(operation string, ph *bmp.PerPeerHeader, update *bgp.Update) (*LSSRv6SID, error) {
	glog.Infof("Available attributes: %+v", update.GetAllAttributeID())
	nlri14, err := update.GetNLRI14()
	if err != nil {
		return nil, err
	}
	nlri71, err := nlri14.GetNLRI71()
	if err != nil {
		return nil, err
	}
	msg := LSSRv6SID{
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
	nlri6, err := nlri71.GetSRv6SIDNLRI()
	if err == nil {
		glog.Infof("nlri6 attributes: %+v", nlri6.GetAllAttribute())
		msg.Protocol = nlri6.GetSRv6SIDProtocolID()
		msg.LocalNodeHash = nlri6.LocalNodeHash
		msg.LSID = nlri6.GetSRv6SIDLSID()
		msg.IGPRouterID = nlri6.GetSRv6SIDIGPRouterID()
		msg.LocalNodeASN = nlri6.GetSRv6SIDASN()
	}
	lsprefix, err := update.GetNLRI29()
	if err == nil {
		glog.Infof("nlri29 attributes: %+v", lsprefix.GetAllAttribute())
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
