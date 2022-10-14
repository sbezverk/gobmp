package message

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

func (p *producer) lsSRv6SID(nlri6 *srv6.SIDNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update) (*LSSRv6SID, error) {
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
		Action:     operation,
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
		PeerType:   uint8(ph.PeerType),
		PeerHash:   ph.GetPeerHash(),
		PeerASN:    ph.PeerAS,
		Timestamp:  ph.GetPeerTimestamp(),
		DomainID:   nlri6.GetIdentifier(),
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
	msg.ProtocolID = nlri6.ProtocolID
	msg.Protocol = nlri6.GetSRv6SIDProtocolID()
	msg.LocalNodeHash = nlri6.LocalNodeHash
	msg.LSID = nlri6.GetSRv6SIDLSID()
	msg.IGPRouterID = nlri6.GetSRv6SIDIGPRouterID()
	msg.LocalNodeASN = nlri6.GetSRv6SIDASN()
	msg.MTID = nlri6.GetSRv6SIDMTID()
	msg.SRv6SID = nlri6.GetSRv6SID()
	ls, err := update.GetNLRI29()
	if err == nil {
		msg.SRv6EndpointBehavior = ls.GetSRv6EndpointBehavior()
		msg.SRv6BGPPeerNodeSID = ls.GetSRv6BGPPeerNodeSID()
		msg.SRv6SIDStructure = ls.GetSRv6SIDStructure()
	}

	return &msg, nil
}
