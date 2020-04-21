package message

import (
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsNode(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) (*LSNode, error) {
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
	msg := LSNode{
		Action:       operation,
		RouterHash:   p.speakerHash,
		RouterIP:     p.speakerIP,
		BaseAttrHash: update.GetBaseAttrHash(),
		PeerHash:     ph.GetPeerHash(),
		PeerASN:      ph.PeerAS,
		Timestamp:    ph.PeerTimestamp,
	}
	msg.Nexthop = nlri.GetNextHop()
	if ph.FlagV {
		// IPv6 specific conversions
		msg.PeerIP = net.IP(ph.PeerAddress).To16().String()
	} else {
		// IPv4 specific conversions
		msg.PeerIP = net.IP(ph.PeerAddress[12:]).To4().String()
	}
	// Processing other nlri and attributes, since they are optional, processing only if they exist
	node, err := nlri71.GetNodeNLRI()
	if err == nil {
		msg.Protocol = node.GetNodeProtocolID()
		msg.IGPRouterID = node.GetNodeIGPRouterID()
		msg.LSID = node.GetNodeLSID()
		msg.ASN = node.GetNodeASN()
		msg.OSPFAreaID = node.GetNodeOSPFAreaID()
	}

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
		msg.SRCapabilities = lsnode.GetNodeSRCapabilities()
		msg.SRAlgorithm = lsnode.GetSRAlgorithm()
		msg.SRLocalBlock = lsnode.GetNodeSRLocalBlock()
		msg.SRv6CapabilitiesTLV = lsnode.GetNodeSRv6CapabilitiesTLV()
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
