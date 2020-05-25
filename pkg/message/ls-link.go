package message

import (
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsLink(link *base.LinkNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update) (*LSLink, error) {
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
		Action:         operation,
		RouterHash:     p.speakerHash,
		RouterIP:       p.speakerIP,
		PeerHash:       ph.GetPeerHash(),
		PeerASN:        ph.PeerAS,
		Timestamp:      ph.PeerTimestamp,
		BaseAttributes: update.BaseAttributes,
	}
	msg.Nexthop = nextHop
	if ph.FlagV {
		// IPv6 specific conversions
		msg.PeerIP = net.IP(ph.PeerAddress).To16().String()
	} else {
		// IPv4 specific conversions
		msg.PeerIP = net.IP(ph.PeerAddress[12:]).To4().String()
	}
	msg.Protocol = link.GetLinkProtocolID()
	msg.LSID = link.GetLinkLSID(true)
	msg.OSPFAreaID = link.GetLinkOSPFAreaID(true)
	msg.LocalLinkID = link.GetLinkID(true)
	msg.RemoteLinkID = link.GetLinkID(false)
	msg.InterfaceIP = link.GetLinkInterfaceAddr()
	msg.NeighborIP = link.GetLinkNeighborAddr()
	msg.LocalNodeHash = link.LocalNodeHash
	msg.RemoteNodeHash = link.RemoteNodeHash
	msg.LocalNodeASN = link.GetLocalASN()
	msg.RemoteNodeASN = link.GetRemoteASN()
	msg.RemoteIGPRouterID = link.GetRemoteIGPRouterID()
	msg.IGPRouterID = link.GetLocalIGPRouterID()

	if lslink, err := update.GetNLRI29(); err == nil {
		if ph.FlagV {
			msg.RouterID = lslink.GetLocalIPv6RouterID()
			msg.RemoteRouterID = lslink.GetRemoteIPv6RouterID()
		} else {
			msg.RouterID = lslink.GetLocalIPv4RouterID()
			msg.RemoteRouterID = lslink.GetRemoteIPv4RouterID()
		}
		msg.MTID = lslink.GetMTID()
		msg.ISISAreaID = lslink.GetISISAreaID()
		msg.LinkMSD = lslink.GetLinkMSD()
		msg.IGPMetric = lslink.GetIGPMetric()
		msg.TEDefaultMetric = lslink.GetTEDefaultMetric()
		msg.AdminGroup = lslink.GetAdminGroup()
		msg.MaxLinkBW = lslink.GetMaxLinkBandwidth()
		msg.MaxResvBW = lslink.GetMaxReservableLinkBandwidth()
		msg.UnResvBW = lslink.GetUnreservedLinkBandwidth()
		msg.TEDefaultMetric = lslink.GetTEDefaultMetric()
		msg.LinkProtection = lslink.GetLinkProtectionType()
		msg.MPLSProtoMask = lslink.GetLinkMPLSProtocolMask()
		msg.SRLG = lslink.GetSRLG()
		msg.LinkName = lslink.GetLinkName()
		msg.SRv6BGPPeerNodeSID = lslink.GetSRv6BGPPeerNodeSID()
		if sid, err := lslink.GetLSSRv6ENDXSID(); err == nil {
			msg.SRv6ENDXSID = sid
		}
		msg.UnidirAvailableBW = lslink.GetUnidirAvailableBandwidth()
		msg.UnidirBWUtilization = lslink.GetUnidirUtilizedBandwidth()
		msg.UnidirDelayVariation = lslink.GetUnidirDelayVariation()
		msg.UnidirLinkDelay = lslink.GetUnidirLinkDelay()
		msg.UnidirLinkDelayMinMax = lslink.GetUnidirLinkDelayMinMax()
		msg.UnidirPacketLoss = lslink.GetUnidirLinkLoss()
		msg.UnidirResidualBW = lslink.GetUnidirResidualBandwidth()
		if adj, err := lslink.GetSRAdjacencySID(); err == nil {
			msg.LSAdjacencySID = adj
		}
	}

	return &msg, nil
}
