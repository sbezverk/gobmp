package message

import (
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// l3vpn process MP_REACH_NLRI AFI 1/2 SAFI 128 update message and returns
// L3VPN prefix object.
func (p *producer) l3vpn(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) (*L3VPNPrefix, error) {
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
		glog.Infof("Delete operation for L3VPN prefix: %s", net.IP(nlril3vpn.GetL3VPNPrefix()).To4().String())
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	prfx := L3VPNPrefix{
		Action:     operation,
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
		PeerHash:   ph.GetPeerHash(),
		PeerASN:    ph.PeerAS,
		Timestamp:  ph.PeerTimestamp,
		Prefix:     net.IP(nlril3vpn.GetL3VPNPrefix()).To4().String(),
		Nexthop:    nlri.GetNextHop(),
		// TODO, why 32 is hard coded here?????
		PrefixLen:      32,
		PathID:         int32(nlril3vpn.PathID),
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
	prfx.VPNRD = nlril3vpn.RD.String()
	prfx.VPNRDType = nlril3vpn.RD.Type

	return &prfx, nil
}
