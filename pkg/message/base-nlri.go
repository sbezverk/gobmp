package message

import (
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// nlri process base nlri information found and bgp update message and returns
// a slice of UnicatPrefix.
// Used Only by Legacy IPv4 Unicast
func (p *producer) nlri(op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]*UnicastPrefix, error) {
	var operation string
	var routes []base.Route
	pathID := p.GetAddPathCapability(ph.GetTableKey())[bgp.NLRIMessageType(1, 1)]
	switch op {
	case 0:
		operation = "add"
		if r, err := base.UnmarshalRoutes(update.NLRI, pathID); err == nil {
			routes = r
		} else {
			return nil, fmt.Errorf("failed to unmarshal routes from NLRI with error: %+v", err)
		}
	case 1:
		operation = "del"
		if r, err := base.UnmarshalRoutes(update.WithdrawnRoutes, pathID); err == nil {
			routes = r
		} else {
			return nil, fmt.Errorf("failed to unmarshal routes from NLRI with error: %+v", err)
		}
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}
	prfxs := make([]*UnicastPrefix, 0)
	// Check if Update carries any routes, if update comes with 0 routes, it is EoR message
	if len(routes) == 0 {
		return []*UnicastPrefix{
			{
				Action:     operation,
				RouterHash: p.speakerHash,
				RouterIP:   p.speakerIP,
				PeerHash:   ph.GetPeerHash(),
				PeerASN:    ph.PeerAS,
				Timestamp:  ph.GetPeerTimestamp(),
				PeerType:   uint8(ph.PeerType),
				IsEOR:      true,
			},
		}, nil
	}
	for _, pr := range routes {
		prfx := &UnicastPrefix{
			Action:         operation,
			RouterHash:     p.speakerHash,
			RouterIP:       p.speakerIP,
			PeerHash:       ph.GetPeerHash(),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.GetPeerTimestamp(),
			PeerType:       uint8(ph.PeerType),
			PrefixLen:      int32(pr.Length),
			PathID:         int32(pr.PathID),
			BaseAttributes: update.BaseAttributes,
		}
		if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
			// Last element in AS_PATH would be the AS of the origin
			prfx.OriginAS = ases[len(ases)-1]
		}
		prfx.IsIPv4 = true
		// Cap IPv4 prefix lengths at 32 bits, avoiding excessive len calc
		if prfx.PrefixLen > 32 {
			if glog.V(6) {
				glog.Warningf("Capping excessive IPv4 prefix length %d to 32 for prefix %s",
					prfx.PrefixLen, pr.Prefix)
			}
			prfx.PrefixLen = 32
		}
		prfx.PeerIP = ph.GetPeerAddrString()
		prfx.Nexthop = update.BaseAttributes.Nexthop
		prfx.IsNexthopIPv4 = true
		a := make([]byte, 4)
		copy(a, pr.Prefix)
		prfx.Prefix = net.IP(a).To4().String()
		if f, err := ph.IsAdjRIBInPost(); err == nil {
			prfx.IsAdjRIBInPost = f
		}
		if f, err := ph.IsAdjRIBOutPost(); err == nil {
			prfx.IsAdjRIBOutPost = f
		}
		if f, err := ph.IsLocRIBFiltered(); err == nil {
			prfx.IsLocRIBFiltered = f
		}
		if ph.PeerType == bmp.PeerType3 {
			prfx.IsLocRIB = true
			prfx.TableName = p.GetTableName(ph.GetPeerBGPIDString(), ph.GetPeerDistinguisherString())
		}
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}
