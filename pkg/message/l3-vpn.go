package message

import (
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// l3vpn process MP_REACH_NLRI AFI 1/2 SAFI 128 update message and returns
// L3VPN prefix object.
func (p *producer) l3vpn(op int, ph *bmp.PerPeerHeader, update *bgp.Update) (*L3VPNPrefix, error) {
	nlri14, err := update.GetNLRI14()
	if err != nil {
		return nil, err
	}
	nlril3vpn, err := nlri14.GetNLRIL3VPN()
	if err != nil {
		return nil, err
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

	prfx := L3VPNPrefix{
		Action:       operation,
		RouterHash:   p.speakerHash,
		RouterIP:     p.speakerIP,
		BaseAttrHash: update.GetBaseAttrHash(),
		PeerHash:     ph.GetPeerHash(),
		PeerASN:      ph.PeerAS,
		Timestamp:    ph.PeerTimestamp,
		Prefix:       net.IP(nlril3vpn.GetL3VPNPrefix()).To4().String(),
		Nexthop:      nlri14.GetNextHop(),
		PrefixLen:    32,
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
	if ph.FlagV {
		// IPv6 specific conversions
		prfx.IsIPv4 = false
		prfx.PeerIP = net.IP(ph.PeerAddress).To16().String()
		prfx.IsNexthopIPv4 = false
	} else {
		// IPv4 specific conversions
		prfx.IsIPv4 = true
		prfx.PeerIP = net.IP(ph.PeerAddress[12:]).To4().String()
		prfx.IsNexthopIPv4 = true
	}
	prfx.Labels = make([]uint32, 0)
	for _, l := range nlril3vpn.Labels {
		prfx.Labels = append(prfx.Labels, l.Value)
	}
	exts, err := update.GetAttrExtCommunity()
	if err == nil {
		for i, ext := range exts {
			prfx.ExtCommunityList += ext.String()
			if i < len(exts)-1 {
				prfx.ExtCommunityList += ", "
			}
		}
	}
	prfx.VPNRD = nlril3vpn.RD.String()
	prfx.VPNRDType = nlril3vpn.RD.Type

	return &prfx, nil
}
