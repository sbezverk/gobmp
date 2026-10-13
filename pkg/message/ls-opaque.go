package message

import (
	"encoding/hex"
	"fmt"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// lsOpaque builds the message for a BGP-LS NLRI of a type gobmp does not
// decode, so it is propagated rather than dropped (RFC 9552 §5.2).
func (p *producer) lsOpaque(nlriType uint16, nlri interface{}, safi uint8, nextHop string, op int, ph *bmp.PerPeerHeader) (*LSOpaque, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}
	value, ok := nlri.([]byte)
	if !ok {
		return nil, fmt.Errorf("bgp-ls NLRI type %d: expected raw []byte value, got %T", nlriType, nlri)
	}
	msg := LSOpaque{
		Action:     operation,
		RouterHash: ph.Identity.RouterHash,
		RouterIP:   ph.Identity.RouterIP,
		PeerType:   uint8(ph.PeerType),
		PeerHash:   ph.GetPeerHash(),
		PeerIP:     ph.GetPeerAddrString(),
		PeerASN:    ph.PeerAS,
		Timestamp:  ph.GetPeerTimestamp(),
		Nexthop:    nextHop,
		SAFI:       safi,
		NLRIType:   nlriType,
		NLRI:       hex.EncodeToString(value),
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
	return &msg, nil
}
