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
		Action:     operation,
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
		PeerHash:   ph.GetPeerHash(),
		PeerASN:    ph.PeerAS,
		Timestamp:  ph.GetPeerTimestamp(),
		DomainID:   node.GetIdentifier(),
	}
	if ph.FlagV {
		// IPv6 specific conversions
		msg.PeerIP = net.IP(ph.PeerAddress).To16().String()
	} else {
		// IPv4 specific conversions
		msg.PeerIP = net.IP(ph.PeerAddress[12:]).To4().String()
	}
	msg.Protocol = node.GetNodeProtocolID()
	msg.ProtocolID = node.ProtocolID
	msg.IGPRouterID = node.GetNodeIGPRouterID()
	msg.LSID = node.GetNodeLSID()
	msg.ASN = node.GetNodeASN()
	switch node.ProtocolID {
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		msg.AreaID = node.GetNodeOSPFAreaID()
	}

	lsnode, err := update.GetNLRI29()
	if err == nil {
		if f, err := lsnode.GetNodeFlags(); err == nil {
			msg.NodeFlags = f
		}
		msg.Name = lsnode.GetNodeName()
		msg.MTID = lsnode.GetMTID()
		switch node.ProtocolID {
		case base.ISISL1:
			fallthrough
		case base.ISISL2:
			msg.AreaID = lsnode.GetISISAreaID()
		}
		if ph.FlagV {
			msg.RouterID = lsnode.GetLocalIPv6RouterID()
		} else {
			msg.RouterID = lsnode.GetLocalIPv4RouterID()
		}
		if msd, err := lsnode.GetNodeMSD(); err == nil {
			msg.NodeMSD = msd
		}
		if cap, err := lsnode.GetNodeSRCapabilities(msg.ProtocolID); err == nil {
			msg.SRCapabilities = cap
		}
		msg.SRAlgorithm = lsnode.GetSRAlgorithm()
		msg.SRLocalBlock = lsnode.GetNodeSRLocalBlock()
		if cap, err := lsnode.GetNodeSRv6CapabilitiesTLV(); err == nil {
			msg.SRv6CapabilitiesTLV = cap
		}
		if fad, err := lsnode.GetFlexAlgoDefinition(); err == nil {
			msg.FlexAlgoDefinition = fad
		}
	}

	return &msg, nil
}
