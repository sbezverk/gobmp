package message

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) lsNode(node *base.NodeNLRI, _ /* place holder for the next hop */ string,
	op int, ph *bmp.PerPeerHeader, update *bgp.Update, isIPv6 bool) (*LSNode, error) {
	localIP, localHash := p.peerLocal(ph.GetTableKey())
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
		Action:        operation,
		RouterHash:    localHash,
		RouterIP:      localIP,
		TransportIP:   p.transportIP,
		TransportHash: p.transportHash,
		PeerType:      uint8(ph.PeerType),
		PeerHash:      ph.GetPeerHash(),
		PeerASN:       ph.PeerAS,
		Timestamp:     ph.GetPeerTimestamp(),
		DomainID:      node.GetIdentifier(),
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
	// RFC 9069: Set TableName for LocRIB peers
	if msg.IsLocRIB {
		msg.TableName = p.GetTableName(ph.GetPeerBGPIDString(), ph.GetPeerDistinguisherString())
	}
	msg.PeerIP = ph.GetPeerAddrString()
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
	case base.ISISL1, base.ISISL2, base.Direct, base.Static, base.BGP, base.RSVPTE, base.SR:
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
		case base.OSPFv2, base.Direct, base.Static, base.OSPFv3, base.BGP, base.RSVPTE, base.SR:
		}
		if isIPv6 {
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
