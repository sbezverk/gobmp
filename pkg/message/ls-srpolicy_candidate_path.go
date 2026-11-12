package message

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/srpolicycp"
)

func (p *producer) lsSSRPolicyCandidatePath(nlri *srpolicycp.SrPolicyCandidatePathNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update) (*LSSrPolicyCandidatePath, error) {
	if p == nil {
		return nil, fmt.Errorf("producer is nil")
	}
	if nlri == nil {
		return nil, fmt.Errorf("sr policy candidate path nlri is nil")
	}
	if nlri.LocalNode == nil {
		return nil, fmt.Errorf("sr policy candidate path local node is nil")
	}
	if nlri.Descriptor == nil {
		return nil, fmt.Errorf("sr policy candidate path descriptor is nil")
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
	msg := LSSrPolicyCandidatePath{
		Action:     operation,
		RouterHash: ph.Identity.RouterHash,
		RouterIP:   ph.Identity.RouterIP,
		PeerType:   uint8(ph.PeerType),
		PeerHash:   ph.GetPeerHash(),
		PeerASN:    ph.PeerAS,
		Timestamp:  ph.GetPeerTimestamp(),
		DomainID:   int64(binary.BigEndian.Uint64(nlri.Identifier)),
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
		msg.TableName = p.getTableName(ph)
	}
	msg.Nexthop = nextHop
	msg.PeerIP = ph.GetPeerAddrString()
	msg.ProtocolID = nlri.ProtocolID
	msg.Protocol = base.ProtocolIDString(nlri.ProtocolID)
	msg.LocalNodeHash = nlri.LocalNodeHash
	msg.LSID = nlri.LocalNode.GetLSID()
	msg.IGPRouterID = nlri.LocalNode.GetIGPRouterIDWithProtocol(nlri.ProtocolID)
	msg.LocalNodeASN = nlri.LocalNode.GetASN()
	msg.Descriptor = nlri.Descriptor
	if id := nlri.LocalNode.GetLocalNodeIPv4RouterID(); id != nil {
		if lid := netip.AddrFrom4([4]byte(id)); lid.IsValid() {
			msg.LocalIPv4RouterID = lid.String()
		}
	}
	if id := nlri.LocalNode.GetLocalNodeIPv6RouterID(); id != nil {
		if lid := netip.AddrFrom16([16]byte(id)); lid.IsValid() {
			msg.LocalIPv6RouterID = lid.String()
		}
	}
	// ls, err := update.GetBGPLSAttribute()
	// if err == nil {
	// 	msg.SRv6EndpointBehavior = ls.GetSRv6EndpointBehavior()
	// 	msg.SRv6BGPPeerNodeSID = ls.GetSRv6BGPPeerNodeSID()
	// 	msg.SRv6SIDStructure = ls.GetSRv6SIDStructure()
	// }

	return &msg, nil
}
