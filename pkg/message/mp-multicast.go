package message

import (
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// multicast process nlri 14 afi 1/2 safi 2 messages and generates MulticastPrefix messages
func (p *producer) multicast(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]*MulticastPrefix, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	prfxs := make([]*MulticastPrefix, 0)
	u, err := nlri.GetNLRIMulticast()
	if err != nil {
		return nil, err
	}

	if len(u.NLRI) == 0 {
		return []*MulticastPrefix{
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
	for _, e := range u.NLRI {
		prfx := &MulticastPrefix{
			Action:         operation,
			RouterHash:     p.speakerHash,
			RouterIP:       p.speakerIP,
			PeerType:       uint8(ph.PeerType),
			PeerHash:       ph.GetPeerHash(),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.GetPeerTimestamp(),
			PrefixLen:      int32(e.Length),
			PathID:         int32(e.PathID),
			BaseAttributes: update.BaseAttributes,
		}
		if f, err := ph.IsAdjRIBInPost(); err == nil {
			prfx.IsAdjRIBInPost = f
		}
		if f, err := ph.IsAdjRIBOutPost(); err == nil {
			prfx.IsAdjRIBOutPost = f
		}
		if f, err := ph.IsLocRIBFiltered(); err == nil {
			prfx.IsLocRIBFiltered = f
		}
		if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
			prfx.OriginAS = ases[len(ases)-1]
		}
		prfx.PeerIP = ph.GetPeerAddrString()
		prfx.Nexthop = nlri.GetNextHop()
		if nlri.IsIPv6NLRI() {
			prfx.IsIPv4 = false
			prfx.IsNexthopIPv4 = false
			a := make([]byte, 16)
			copy(a, e.Prefix)
			prfx.Prefix = net.IP(a).To16().String()
		} else {
			prfx.IsIPv4 = true
			prfx.IsNexthopIPv4 = true
			a := make([]byte, 4)
			copy(a, e.Prefix)
			prfx.Prefix = net.IP(a).To4().String()
			if prfx.PrefixLen > 32 {
				if glog.V(6) {
					glog.Warningf("Capping excessive IPv4 prefix length %d to 32 for prefix %s",
						prfx.PrefixLen, prfx.Prefix)
				}
				prfx.PrefixLen = 32
			}
		}
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}
