package message

import (
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/unicast"
)

// unicast process nlri 14 afi 1/2 safi 1 messages and generates UnicastPrefix messages
func (p *producer) unicast(op int, ph *bmp.PerPeerHeader, update *bgp.Update, label bool, ipv4 bool) ([]UnicastPrefix, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	nlri14, err := update.GetNLRI14()
	if err != nil {
		return nil, err
	}
	prfxs := make([]UnicastPrefix, 0)
	var u *unicast.MPUnicastNLRI
	if label {
		u, err = nlri14.GetNLRILU()
		if err != nil {
			return nil, err
		}
	} else {
		u, err = nlri14.GetNLRIUnicast()
		if err != nil {
			return nil, err
		}
	}
	for _, e := range u.NLRI {
		glog.Infof("MP Labeled Unicast prefix: %+v", p)
		prfx := UnicastPrefix{
			Action:       operation,
			RouterHash:   p.speakerHash,
			RouterIP:     p.speakerIP,
			BaseAttrHash: update.GetBaseAttrHash(),
			PeerHash:     ph.GetPeerHash(),
			PeerASN:      ph.PeerAS,
			Timestamp:    ph.PeerTimestamp,
			PrefixLen:    int32(e.Length),
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
		if !ipv4 {
			// IPv6 specific conversions
			prfx.IsIPv4 = false
			prfx.PeerIP = net.IP(ph.PeerAddress).To16().String()
			prfx.Nexthop = net.IP(update.GetAttrNextHop()).To16().String()
			prfx.IsNexthopIPv4 = false
			a := make([]byte, 16)
			copy(a, e.Prefix)
			prfx.Prefix = net.IP(a).To16().String()
		} else {
			// IPv4 specific conversions
			prfx.IsIPv4 = true
			prfx.PeerIP = net.IP(ph.PeerAddress[12:]).To4().String()
			prfx.Nexthop = net.IP(update.GetAttrNextHop()).To4().String()
			prfx.IsNexthopIPv4 = true
			a := make([]byte, 4)
			copy(a, e.Prefix)
			prfx.Prefix = net.IP(a).To4().String()
		}
		if label {
			for _, l := range e.Label {
				prfx.Labels = append(prfx.Labels, l.Value)
			}
		}
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}
