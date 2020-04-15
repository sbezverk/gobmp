package message

import (
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// evpn process MP_REACH_NLRI AFI 25 SAFI 70 update message and returns
// EVPN prefix object.
func (p *producer) evpn(op int, ph *bmp.PerPeerHeader, update *bgp.Update) (*EVPNPrefix, error) {
	nlri14, err := update.GetNLRI14()
	if err != nil {
		return nil, err
	}
	glog.Infof("All attributes in evpn upate: %+v", update.GetAllAttributeID())
	_, err = nlri14.GetNLRIEVPN()
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

	prfx := EVPNPrefix{
		Action:       operation,
		RouterHash:   p.speakerHash,
		RouterIP:     p.speakerIP,
		BaseAttrHash: update.GetBaseAttrHash(),
		PeerHash:     ph.GetPeerHash(),
		PeerASN:      ph.PeerAS,
		Timestamp:    ph.PeerTimestamp,
		Nexthop:      nlri14.GetNextHop(),
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
	exts, err := update.GetAttrExtCommunity()
	if err == nil {
		for i, ext := range exts {
			prfx.ExtCommunityList += ext.String()
			if i < len(exts)-1 {
				prfx.ExtCommunityList += ", "
			}
		}
	}

	return &prfx, nil
}
