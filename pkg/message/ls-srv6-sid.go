package message

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsSRv6SID(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) (*LSSRv6SID, error) {
	nlri71, err := nlri.GetNLRI71()
	if err != nil {
		return nil, err
	}
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
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
	msg.Nexthop = nlri.GetNextHop()
	msg.PeerIP = ph.GetPeerAddrString()
	// Processing other nlri and attributes, since they are optional, processing only if they exist
	nlri6, err := nlri71.GetSRv6SIDNLRI()
	if err == nil {
		glog.V(6).Infof("nlri6 attributes: %+v", nlri6.GetAllAttribute())
		msg.Protocol = nlri6.GetSRv6SIDProtocolID()
		msg.LocalNodeHash = nlri6.LocalNodeHash
		msg.LSID = nlri6.GetSRv6SIDLSID()
		msg.IGPRouterID = nlri6.GetSRv6SIDIGPRouterID()
		msg.LocalNodeASN = nlri6.GetSRv6SIDASN()
		msg.MTID = nlri6.GetSRv6SIDMTID()
		msg.SRv6SID = nlri6.GetSRv6SID()
	}
	ls, err := update.GetNLRI29()
	if err == nil {
		glog.V(6).Infof("nlri29 attributes: %+v", ls.GetAllAttribute())
		msg.SRv6EndpointBehavior = ls.GetSRv6EndpointBehavior()
		msg.SRv6BGPPeerNodeSID = ls.GetSRv6BGPPeerNodeSID()
		msg.SRv6SIDStructure = ls.GetSRv6SIDStructure()
	}
	msg.ASPath = update.GetAttrASPath()
	if med := update.GetAttrMED(); med != nil {
		msg.MED = *med
	}
	if lp := update.GetAttrLocalPref(); lp != nil {
		msg.LocalPref = *lp
	}

	return &msg, nil
}
