package message

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/srpolicycp"
)

func (p *producer) lsSSRPolicyCandidatePath(nlri *srpolicycp.SrPolicyCandidatePathNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update) (*LSSrPolicyCandidatePath, error) {
	return p.lsSSRPolicyCandidatePathForSAFI(nlri, nextHop, op, ph, update, 71, "")
}

func (p *producer) lsSSRPolicyCandidatePathForSAFI(nlri *srpolicycp.SrPolicyCandidatePathNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update, safi uint8, rd string) (*LSSrPolicyCandidatePath, error) {
	if p == nil {
		return nil, fmt.Errorf("producer is nil")
	}
	if ph == nil {
		return nil, fmt.Errorf("peer header is nil")
	}
	if nlri == nil {
		return nil, fmt.Errorf("sr policy candidate path nlri is nil")
	}
	if len(nlri.Identifier) != 8 {
		return nil, fmt.Errorf("sr policy candidate path identifier has length %d, want 8", len(nlri.Identifier))
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
		SAFI:       safi,
		RD:         rd,
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
	if update != nil {
		if ls, err := update.GetBGPLSAttribute(); err != nil {
			glog.Warningf("failed to decode BGP-LS Attribute for SR Policy Candidate Path: %v", err)
		} else if state, err := ls.GetSRPolicyState(); err != nil {
			glog.Warningf("failed to decode SR Policy State: %v", err)
		} else if state.HasData() {
			msg.PolicyState = state
		}
	}

	return &msg, nil
}
