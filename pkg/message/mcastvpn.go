package message

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/mcastvpn"
)

// mcastvpn processes MP_REACH_NLRI/MP_UNREACH_NLRI AFI 1/2 SAFI 5 (MCAST-VPN)
func (p *producer) mcastvpn(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]*MCASTVPNPrefix, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	prfxs := make([]*MCASTVPNPrefix, 0)
	mcastvpnRoute, err := nlri.GetNLRIMCASTVPN()
	if err != nil {
		return nil, err
	}

	// Handle EOR (End-of-RIB) when no NLRIs present
	if len(mcastvpnRoute.Route) == 0 {
		return []*MCASTVPNPrefix{
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

	for _, route := range mcastvpnRoute.Route {
		prfx := &MCASTVPNPrefix{
			Action:         operation,
			RouterHash:     p.speakerHash,
			RouterIP:       p.speakerIP,
			PeerType:       uint8(ph.PeerType),
			PeerHash:       ph.GetPeerHash(),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.GetPeerTimestamp(),
			RouteType:      route.RouteType,
			BaseAttributes: update.BaseAttributes,
		}

		// Set RIB flags
		if f, err := ph.IsAdjRIBInPost(); err == nil {
			prfx.IsAdjRIBInPost = f
		}
		if f, err := ph.IsAdjRIBOutPost(); err == nil {
			prfx.IsAdjRIBOutPost = f
		}
		if f, err := ph.IsLocRIBFiltered(); err == nil {
			prfx.IsLocRIBFiltered = f
		}

		prfx.PeerIP = ph.GetPeerAddrString()
		prfx.IsIPv4 = !nlri.IsIPv6NLRI()

		// Extract nexthop
		prfx.Nexthop = nlri.GetNextHop()
		prfx.IsNexthopIPv4 = len(nlri.GetNextHop()) > 0 && net.ParseIP(nlri.GetNextHop()).To4() != nil

		// Extract Route Distinguisher if present
		if rd := route.GetMCASTVPNRD(); rd != nil {
			prfx.RD = rd.String()
		}

		// Extract Originating Router IP if present
		if originatorIP := route.GetMCASTVPNOriginatorIP(); len(originatorIP) > 0 {
			if len(originatorIP) == 4 {
				prfx.OriginatorIP = net.IP(originatorIP).To4().String()
			} else if len(originatorIP) == 16 {
				prfx.OriginatorIP = net.IP(originatorIP).To16().String()
			}
		}

		// Extract Multicast Source if present
		if mcastSrc := route.GetMCASTVPNMulticastSource(); len(mcastSrc) > 0 {
			if len(mcastSrc) == 4 {
				prfx.MulticastSource = net.IP(mcastSrc).To4().String()
			} else if len(mcastSrc) == 16 {
				prfx.MulticastSource = net.IP(mcastSrc).To16().String()
			}
		}

		// Extract Multicast Group if present
		if mcastGrp := route.GetMCASTVPNMulticastGroup(); len(mcastGrp) > 0 {
			if len(mcastGrp) == 4 {
				prfx.MulticastGroup = net.IP(mcastGrp).To4().String()
			} else if len(mcastGrp) == 16 {
				prfx.MulticastGroup = net.IP(mcastGrp).To16().String()
			}
		}

		// Extract Source AS if present
		if sourceAS := route.GetMCASTVPNSourceAS(); sourceAS != 0 {
			prfx.SourceAS = sourceAS
		}

		// For Type 4 (Leaf A-D), extract Route Key
		if route.RouteType == 4 {
			if spec := route.GetRouteTypeSpec(); spec != nil {
				// Type 4 specific: encode RouteKey as hex string
				if t4, ok := spec.(*mcastvpn.Type4); ok {
					prfx.RouteKey = hex.EncodeToString(t4.RouteKey)
				}
			}
		}

		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}
