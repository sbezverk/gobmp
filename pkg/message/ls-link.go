package message

import (
	"net"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsLink(operation string, ph *bmp.PerPeerHeader, update *bgp.Update) (*LSLink, error) {
	nlri14, err := update.GetNLRI14()
	if err != nil {
		return nil, err
	}
	nlri71, err := nlri14.GetNLRI71()
	if err != nil {
		return nil, err
	}
	msg := LSLink{
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
	link, err := nlri71.GetLinkNLRI()
	if err == nil {
		msg.Protocol = link.GetLinkProtocolID()
		msg.LSID = link.GetLinkLSID(true)
		msg.OSPFAreaID = link.GetLinkOSPFAreaID(true)
		msg.LocalLinkID = link.GetLinkID(true)
		msg.RemoteLinkID = link.GetLinkID(false)
		if ph.FlagV {
			msg.InterfaceIP = link.GetLinkIPv6InterfaceAddr()
			msg.NeighborIP = link.GetLinkIPv6NeighborAddr()
		} else {
			msg.InterfaceIP = link.GetLinkIPv4InterfaceAddr()
			msg.NeighborIP = link.GetLinkIPv4NeighborAddr()
		}
		msg.LocalNodeHash = link.LocalNodeHash
		msg.RemoteNodeHash = link.RemoteNodeHash
		msg.LocalNodeASN = link.GetLocalASN()
		msg.RemoteNodeASN = link.GetRemoteASN()
		msg.RemoteIGPRouterID = link.GetRemoteIGPRouterID()
		msg.IGPRouterID = link.GetLocalIGPRouterID()
	}
	lslink, err := update.GetNLRI29()
	if err == nil {
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
		msg.PeerNodeSID = lslink.GetSRv6PeerNodeSID()
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
	msg.ASPath = update.GetAttrASPath(p.as4Capable)
	if med := update.GetAttrMED(); med != nil {
		msg.MED = *med
	}
	if lp := update.GetAttrLocalPref(); lp != nil {
		msg.LocalPref = *lp
	}

	return &msg, nil
}
