package message

import (
	"fmt"
	"net"
	"strconv"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsLink(link *base.LinkNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update, isIPv6 bool) (*LSLink, error) {
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
		Action:     operation,
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
		PeerType:   uint8(ph.PeerType),
		PeerHash:   ph.GetPeerHash(),
		PeerASN:    ph.PeerAS,
		Timestamp:  ph.GetPeerTimestamp(),
		DomainID:   link.GetIdentifier(),
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
	msg.Protocol = link.GetLinkProtocolID()
	msg.ProtocolID = link.ProtocolID
	msg.LSID = link.GetLinkLSID(true)
	// Attempting to get Link IDs from Link Descriptor TLVs
	if ids, err := link.GetLinkID(); err == nil {
		msg.LocalLinkID = ids[0]
		msg.RemoteLinkID = ids[1]
	}
	if a := link.GetLinkInterfaceAddr(); a != nil {
		msg.LocalLinkIP = a.String()
	}
	if a := link.GetLinkNeighborAddr(); a != nil {
		msg.RemoteLinkIP = a.String()
	}
	msg.LocalNodeHash = link.LocalNodeHash
	msg.RemoteNodeHash = link.RemoteNodeHash
	msg.LocalNodeASN = link.GetLocalASN()
	msg.RemoteNodeASN = link.GetRemoteASN()
	msg.RemoteIGPRouterID = link.GetRemoteIGPRouterID()
	msg.IGPRouterID = link.GetLocalIGPRouterID()
	msg.MTID = link.Link.GetLinkMTID()
	switch link.ProtocolID {
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
		msg.AreaID = link.LocalNode.GetOSPFAreaID()
	case base.BGP:
		msg.AreaID = strconv.Itoa(int(link.LocalNode.GetASN()))
		msg.BGPRouterID = net.IP(link.LocalNode.GetBGPRouterID()).To4().String()
		msg.BGPRemoteRouterID = net.IP(link.RemoteNode.GetBGPRouterID()).To4().String()
		msg.MemberAS = link.LocalNode.GetConfedMemberASN()
	default:
		msg.AreaID = "0"
	}
	if lslink, err := update.GetNLRI29(); err == nil {
		if isIPv6 {
			msg.RouterID = lslink.GetLocalIPv6RouterID()
			msg.RemoteRouterID = lslink.GetRemoteIPv6RouterID()
		} else {
			msg.RouterID = lslink.GetLocalIPv4RouterID()
			msg.RemoteRouterID = lslink.GetRemoteIPv4RouterID()
		}
		if msd, err := lslink.GetLinkMSD(); err == nil {
			msg.LinkMSD = msd
		}
		// Check if Local and Remote Link ID are already non 0
		if msg.LocalLinkID == 0 && msg.RemoteLinkID == 0 {
			// Attempting to get Local and Remote Link IDs from BGP-LS
			if ids, err := lslink.GetLinkID(); err == nil {
				msg.LocalLinkID = ids[0]
				msg.RemoteLinkID = ids[1]
			}
		}
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
		if aslas, err := lslink.GetAppSpecLinkAttr(); err == nil {
			msg.AppSpecLinkAttr = aslas
		}
		msg.UnidirAvailableBW = lslink.GetUnidirAvailableBandwidth()
		msg.UnidirBWUtilization = lslink.GetUnidirUtilizedBandwidth()
		msg.UnidirDelayVariation = lslink.GetUnidirDelayVariation()
		msg.UnidirLinkDelay = lslink.GetUnidirLinkDelay()
		msg.UnidirLinkDelayMinMax = lslink.GetUnidirLinkDelayMinMax()
		msg.UnidirPacketLoss = lslink.GetUnidirLinkLoss()
		msg.UnidirResidualBW = lslink.GetUnidirResidualBandwidth()
		if adj, err := lslink.GetSRAdjacencySID(msg.ProtocolID); err == nil {
			msg.LSAdjacencySID = adj
		}
		if msg.ProtocolID == base.BGP {
			if sid, err := lslink.GetPeerNodeSID(); err == nil {
				msg.PeerNodeSID = sid
			}
			if sid, err := lslink.GetPeerAdjSID(); err == nil {
				msg.PeerAdjSID = sid
			}
			if sid, err := lslink.GetPeerSetSID(); err == nil {
				msg.PeerSetSID = sid
			}
		}
	}

	return &msg, nil
}
