package message

import (
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// nlri process base nlri information found and bgp update message and returns
// a slice of UnicatPrefix.
func (p *producer) nlri(op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]UnicastPrefix, error) {
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
	for _, pr := range update.NLRI {
		prfx := UnicastPrefix{
			Action:         operation,
			RouterHash:     p.speakerHash,
			RouterIP:       p.speakerIP,
			PeerHash:       ph.GetPeerHash(),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.PeerTimestamp,
			PrefixLen:      int32(pr.Length),
			PathID:         int32(pr.PathID),
			BaseAttributes: update.BaseAttributes,
		}
		if ases := update.GetAttrASPath(); len(ases) != 0 {
			// Last element in AS_PATH would be the AS of the origin
			prfx.OriginAS = fmt.Sprintf("%d", ases[len(ases)-1])
		}
		if ph.FlagV {
			// IPv6 specific conversions
			prfx.IsIPv4 = false
			prfx.PeerIP = net.IP(ph.PeerAddress).To16().String()
			prfx.Nexthop = net.IP(update.GetAttrNextHop()).To16().String()
			prfx.IsNexthopIPv4 = false
			a := make([]byte, 16)
			copy(a, pr.Prefix)
			prfx.Prefix = net.IP(a).To16().String()
		} else {
			// IPv4 specific conversions
			prfx.IsIPv4 = true
			prfx.PeerIP = net.IP(ph.PeerAddress[12:]).To4().String()
			prfx.Nexthop = net.IP(update.GetAttrNextHop()).To4().String()
			prfx.IsNexthopIPv4 = true
			a := make([]byte, 4)
			copy(a, pr.Prefix)
			prfx.Prefix = net.IP(a).To4().String()
		}
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}
