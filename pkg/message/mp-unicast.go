package message

import (
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// unicast process nlri 14 afi 1/2 safi 1 messages and generates UnicastPrefix messages
func (p *producer) unicast(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update, label bool) ([]UnicastPrefix, error) {
	var err error
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	prfxs := make([]UnicastPrefix, 0)
	var u *base.MPNLRI
	if label {
		u, err = nlri.GetNLRILU()
		if err != nil {
			return nil, err
		}
	} else {
		u, err = nlri.GetNLRIUnicast()
		if err != nil {
			return nil, err
		}
	}
	for _, e := range u.NLRI {
		prfx := UnicastPrefix{
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
			// Last element in AS_PATH would be the AS of the origin
			prfx.OriginAS = int32(ases[len(ases)-1])
		}
		prfx.PeerIP = ph.GetPeerAddrString()
		prfx.Nexthop = nlri.GetNextHop()
		if nlri.IsIPv6NLRI() {
			// IPv6 specific conversions
			prfx.IsIPv4 = false
			prfx.IsNexthopIPv4 = false
			a := make([]byte, 16)
			copy(a, e.Prefix)
			prfx.Prefix = net.IP(a).To16().String()
		} else {
			// IPv4 specific conversions
			prfx.IsIPv4 = true
			prfx.IsNexthopIPv4 = true
			a := make([]byte, 4)
			copy(a, e.Prefix)
			prfx.Prefix = net.IP(a).To4().String()
		}
		if label {
			for _, l := range e.Label {
				prfx.Labels = append(prfx.Labels, l.Value)
			}
			// Some Label Unicast may carry BGP Attribute 40 (Prefix SID)
			if psid, err := update.GetAttrPrefixSID(); err == nil {
				prfx.PrefixSID = psid
			}
		}
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}
