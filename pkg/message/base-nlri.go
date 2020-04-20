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
			Action:       operation,
			RouterHash:   p.speakerHash,
			RouterIP:     p.speakerIP,
			BaseAttrHash: update.GetBaseAttrHash(),
			PeerHash:     ph.GetPeerHash(),
			PeerASN:      ph.PeerAS,
			Timestamp:    ph.PeerTimestamp,
			PrefixLen:    int32(pr.Length),
			IsAtomicAgg:  update.GetAttrAtomicAggregate(),
			Aggregator:   fmt.Sprintf("%v", update.GetAttrAS4Aggregator()),
		}
		if oid := update.GetAttrOriginatorID(); len(oid) != 0 {
			prfx.OriginatorID = net.IP(update.GetAttrOriginatorID()).To4().String()
		}
		if o := update.GetAttrOrigin(); o != nil {
			prfx.Origin = *o
		}
		prfx.ASPath = update.GetAttrASPath(p.as4Capable)
		prfx.ASPathCount = int32(len(prfx.ASPath))
		if ases := update.GetAttrASPath(p.as4Capable); len(ases) != 0 {
			// Last element in AS_PATH would be the AS of the origin
			prfx.OriginAS = fmt.Sprintf("%d", ases[len(ases)-1])
		}
		if med := update.GetAttrMED(); med != nil {
			prfx.MED = *med
		}
		if lp := update.GetAttrLocalPref(); lp != nil {
			prfx.LocalPref = *lp
		}
		if coms := update.GetAttrCommunityString(); coms != "" {
			prfx.CommunityList += coms
                }
		if exts, _  := update.GetAttrExtCommunity(); exts != nil {
			for i, ext := range exts {
				prfx.ExtCommunityList += ext.String()
				if i < len(exts)-1 {
					prfx.ExtCommunityList += ", "
				}
			}
		}
		if lgs, _  := update.GetAttrLgCommunity(); lgs != nil {
			for i, lg := range lgs {
				prfx.LgCommunityList += lg.String()
				if i < len(lgs)-1 {
					prfx.LgCommunityList += ", "
				}
			}
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
