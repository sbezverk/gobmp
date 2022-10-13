package message

import (
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// l3vpn process MP_REACH_NLRI AFI 1/2 SAFI 128 update message and returns
// L3VPN prefix object.
func (p *producer) l3vpn(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]L3VPNPrefix, error) {
	nlril3vpn, err := nlri.GetNLRIL3VPN()
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
	prfxs := make([]L3VPNPrefix, 0)
	for _, e := range nlril3vpn.NLRI {
		prfx := L3VPNPrefix{
			Action:         operation,
			RouterHash:     p.speakerHash,
			RouterIP:       p.speakerIP,
			PeerType:       uint8(ph.PeerType),
			PeerHash:       ph.GetPeerHash(),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.GetPeerTimestamp(),
			Nexthop:        nlri.GetNextHop(),
			PrefixLen:      int32(e.Length),
			PathID:         int32(e.PathID),
			BaseAttributes: update.BaseAttributes,
		}

		if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
			// Last element in AS_PATH would be the AS of the origin
			prfx.OriginAS = int32(ases[len(ases)-1])
		}
		if nlri.IsIPv6NLRI() {
			// IPv6 specific conversions
			prfx.IsIPv4 = false
			p := make([]byte, 16)
			copy(p, e.Prefix)
			prfx.Prefix = net.IP(p).To16().String()
		} else {
			// IPv4 specific conversions
			prfx.IsIPv4 = true
			p := make([]byte, 4)
			copy(p, e.Prefix)
			prfx.Prefix = net.IP(p).To4().String()
		}
		prfx.IsNexthopIPv4 = !nlri.IsNextHopIPv6()
		prfx.PeerIP = ph.GetPeerAddrString()
		if f, err := ph.IsAdjRIBInPost(); err == nil {
			prfx.IsAdjRIBInPost = f
		}
		if f, err := ph.IsAdjRIBOutPost(); err == nil {
			prfx.IsAdjRIBOutPost = f
		}
		if f, err := ph.IsLocRIBFiltered(); err == nil {
			prfx.IsLocRIBFiltered = f
		}
		prfx.Labels = make([]uint32, 0)
		for _, l := range e.Label {
			prfx.Labels = append(prfx.Labels, l.Value)
		}
		prfx.VPNRD = e.RD.String()
		prfx.VPNRDType = e.RD.Type
		if psid, err := update.GetAttrPrefixSID(); err == nil {
			prfx.PrefixSID = psid
		}
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}
