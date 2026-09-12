package message

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsInterASLink(link *base.InterASLinkNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update, isIPv6 bool) (*LSLink, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}
	msg := LSLink{
		Action:        operation,
		RouterHash:    ph.Identity.RouterHash,
		RouterIP:      ph.Identity.RouterIP,
		PeerType:      uint8(ph.PeerType),
		PeerHash:      ph.GetPeerHash(),
		PeerASN:       ph.PeerAS,
		Timestamp:     ph.GetPeerTimestamp(),
		DomainID:      link.GetIdentifier(),
		Nexthop:       nextHop,
		PeerIP:        ph.GetPeerAddrString(),
		Protocol:      link.GetProtocolID(),
		ProtocolID:    link.ProtocolID,
		LSID:          link.LocalNode.GetLSID(),
		LocalNodeHash: link.LocalNodeHash,
		LocalNodeASN:  link.LocalNode.GetASN(),
		RemoteNodeASN: link.GetRemoteASN(),
		IGPRouterID:   link.LocalNode.GetIGPRouterID(),
		MTID:          link.Link.GetLinkMTID(),
		IsInterAS:     true,
	}
	if f, err := ph.IsAdjRIBInPost(); err == nil {
		msg.IsAdjRIBInPost = f
	}
	if f, err := ph.IsAdjRIBOutPost(); err == nil {
		msg.IsAdjRIBOutPost = f
	}
	if f, err := ph.IsAdjRIBOut(); err == nil {
		msg.IsAdjRIBOut = f
	}
	if f, err := ph.IsLocRIB(); err == nil {
		msg.IsLocRIB = f
	}
	if f, err := ph.IsLocRIBFiltered(); err == nil {
		msg.IsLocRIBFiltered = f
	}
	if msg.IsLocRIB {
		msg.TableName = p.GetTableName(ph.GetPeerBGPIDString(), ph.GetPeerDistinguisherString())
	}
	if ids, err := link.Link.GetLinkID(); err == nil {
		msg.LocalLinkID = ids[0]
		msg.RemoteLinkID = ids[1]
	}
	if address := link.Link.GetLinkIPv4InterfaceAddr(); address != nil {
		msg.LocalLinkIPv4 = address.String()
		msg.LocalLinkIP = msg.LocalLinkIPv4
	}
	if address := link.Link.GetLinkIPv6InterfaceAddr(); address != nil {
		msg.LocalLinkIPv6 = address.String()
		if msg.LocalLinkIP == "" {
			msg.LocalLinkIP = msg.LocalLinkIPv6
		}
	}
	if address := link.Link.GetLinkIPv4NeighborAddr(); address != nil {
		msg.RemoteLinkIPv4 = address.String()
		msg.RemoteLinkIP = msg.RemoteLinkIPv4
	}
	if address := link.Link.GetLinkIPv6NeighborAddr(); address != nil {
		msg.RemoteLinkIPv6 = address.String()
		if msg.RemoteLinkIP == "" {
			msg.RemoteLinkIP = msg.RemoteLinkIPv6
		}
	}
	if address := link.GetLocalASBRIPv4(); address != nil {
		msg.LocalASBRIPv4 = address.String()
	}
	if address := link.GetLocalASBRIPv6(); address != nil {
		msg.LocalASBRIPv6 = address.String()
	}
	if address := link.GetRemoteASBRIPv4(); address != nil {
		msg.RemoteASBRIPv4 = address.String()
	}
	if address := link.GetRemoteASBRIPv6(); address != nil {
		msg.RemoteASBRIPv6 = address.String()
	}
	switch link.ProtocolID {
	case base.OSPFv2, base.OSPFv3:
		msg.AreaID = link.LocalNode.GetOSPFAreaID()
	default:
		msg.AreaID = "0"
	}
	populateLSLinkAttributes(&msg, update, isIPv6)
	return &msg, nil
}
