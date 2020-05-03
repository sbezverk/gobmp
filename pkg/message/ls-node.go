package message

import (
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsNode(node *base.NodeNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update) (*LSNode, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}
	msg := LSNode{
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
	msg.Protocol = node.GetNodeProtocolID()
	msg.IGPRouterID = node.GetNodeIGPRouterID()
	msg.LSID = node.GetNodeLSID()
	msg.ASN = node.GetNodeASN()
	msg.OSPFAreaID = node.GetNodeOSPFAreaID()
	lsnode, err := update.GetNLRI29()
	if err == nil {
		msg.Flags = lsnode.GetNodeFlags()
		msg.Name = lsnode.GetNodeName()
		msg.MTID = lsnode.GetMTID()
		msg.ISISAreaID = lsnode.GetISISAreaID()
		if ph.FlagV {
			msg.RouterID = lsnode.GetLocalIPv6RouterID()
		} else {
			msg.RouterID = lsnode.GetLocalIPv4RouterID()
		}
		msg.NodeMSD = lsnode.GetNodeMSD()
		if cap, err := lsnode.GetNodeSRCapabilities(); err == nil {
			msg.SRCapabilities = cap
		}
		msg.SRAlgorithm = lsnode.GetSRAlgorithm()
		msg.SRLocalBlock = lsnode.GetNodeSRLocalBlock()
		msg.SRv6CapabilitiesTLV = lsnode.GetNodeSRv6CapabilitiesTLV()
	}

	return &msg, nil
}
