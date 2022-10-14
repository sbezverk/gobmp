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
func (p *producer) evpn(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]EVPNPrefix, error) {
	if glog.V(6) {
		glog.Infof("All attributes in evpn update: %+v", update.GetAllAttributeID())
	}
	evpn, err := nlri.GetNLRIEVPN()
	if err != nil {
		return nil, err
	}
	prfxs := make([]EVPNPrefix, 0)
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	for _, e := range evpn.Route {
		prfx := EVPNPrefix{
			Action:         operation,
			PeerType:       uint8(ph.PeerType),
			RouterHash:     p.speakerHash,
			RouterIP:       p.speakerIP,
			PeerHash:       ph.GetPeerHash(),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.GetPeerTimestamp(),
			Nexthop:        nlri.GetNextHop(),
			BaseAttributes: update.BaseAttributes,
		}
		if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
			// Last element in AS_PATH would be the AS of the origin
			prfx.OriginAS = int32(ases[len(ases)-1])
		}

		prfx.PeerIP = ph.GetPeerAddrString()
		prfx.RemoteBGPID = ph.GetPeerBGPIDString()
		prfx.IsIPv4 = !nlri.IsIPv6NLRI()
		prfx.IsNexthopIPv4 = !nlri.IsNextHopIPv6()

		// Do not want to panic on nil pointer
		if e != nil {
			prfx.VPNRD = e.GetEVPNRD()
			prfx.RouteType = e.GetEVPNRouteType()
			esi := e.GetEVPNESI()
			if esi != nil {
				// TODO Change 10 for a const for ESI length
				for i := 0; i < 10; i++ {
					prfx.ESI += fmt.Sprintf("%02d", esi[i])
					// TODO same here ESI length -1
					if i < 9 {
						prfx.ESI += ":"
					}
				}
			}
			prfx.EthTag = e.GetEVPNTAG()
			if ip := e.GetEVPNIPLength(); ip != nil {
				prfx.IPLength = *ip
				gw := e.GetEVPNGWAddr()
				addr := e.GetEVPNIPAddr()
				// IPv4 should have IPLength set to 32
				if prfx.IPLength <= 32 {
					if addr != nil {
						prfx.IPAddress = net.IP(addr).To4().String()
					}
					if gw != nil {
						prfx.GWAddress = net.IP(gw).To4().String()
					}
				}
				// Processing IPv6 IP and GW
				if prfx.IPLength <= 128 {
					if addr != nil {
						prfx.IPAddress = net.IP(addr).To16().String()
					}
					if gw != nil {
						prfx.GWAddress = net.IP(gw).To16().String()
					}
				}
			}
			if mac := e.GetEVPNMACLength(); mac != nil {
				prfx.MACLength = *mac
				v := e.GetEVPNMAC()
				for i := 0; i < int(prfx.MACLength/8); i++ {
					prfx.MAC += fmt.Sprintf("%02x", v[i])
					if i < int(prfx.MACLength/8)-1 {
						prfx.MAC += ":"
					}
				}
			}

			for _, l := range e.GetEVPNLabel() {
				prfx.Labels = append(prfx.Labels, l.Value)
				prfx.RawLabels = append(prfx.RawLabels, l.GetRawValue())
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
		}
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}
