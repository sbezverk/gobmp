package message

import (
	"errors"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	evpnpkg "github.com/sbezverk/gobmp/pkg/evpn"
)

const (
	// ESILength defines the Ethernet Segment Identifier length in bytes (RFC 7432 Section 5)
	ESILength = 10
)

// evpn process MP_REACH_NLRI AFI 25 SAFI 70 update message and returns
// EVPN prefix object.
func (p *producer) evpn(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]EVPNPrefix, error) {
	if glog.V(6) {
		glog.Infof("All attributes in evpn update: %+v", update.GetAllAttributeID())
	}
	evpn, err := nlri.GetNLRIEVPN()
	if errors.Is(err, evpnpkg.ErrEmptyNLRI) && op == DelPrefix {
		// Only an empty MP_UNREACH_NLRI is End-of-RIB (RFC 4724 §2); an empty MP_REACH is not.
		afi, safi := mpFamily(nlri)
		prfx := EVPNPrefix{
			Action:      "del",
			RouterHash:  ph.Identity.RouterHash,
			RouterIP:    ph.Identity.RouterIP,
			PeerHash:    ph.GetPeerHash(),
			PeerIP:      ph.GetPeerAddrString(),
			RemoteBGPID: ph.GetPeerBGPIDString(),
			PeerASN:     ph.PeerAS,
			Timestamp:   ph.GetPeerTimestamp(),
			PeerType:    uint8(ph.PeerType),
			IsEOR:       true,
			AFI:         afi,
			SAFI:        safi,
			IsIPv4:      !nlri.IsIPv6NLRI(),
		}
		if f, err := ph.IsAdjRIBInPost(); err == nil {
			prfx.IsAdjRIBInPost = f
		}
		if f, err := ph.IsAdjRIBOutPost(); err == nil {
			prfx.IsAdjRIBOutPost = f
		}
		if f, err := ph.IsAdjRIBOut(); err == nil {
			prfx.IsAdjRIBOut = f
		}
		if f, err := ph.IsLocRIB(); err == nil {
			prfx.IsLocRIB = f
		}
		if f, err := ph.IsLocRIBFiltered(); err == nil {
			prfx.IsLocRIBFiltered = f
		}
		if prfx.IsLocRIB {
			prfx.TableName = p.GetTableName(ph.GetPeerBGPIDString(), ph.GetPeerDistinguisherString())
		}
		return []EVPNPrefix{prfx}, nil
	}
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

	nextHop := nlri.GetNextHop()
	for _, e := range evpn.Route {
		prfx := EVPNPrefix{
			Action:         operation,
			PeerType:       uint8(ph.PeerType),
			RouterHash:     ph.Identity.RouterHash,
			RouterIP:       ph.Identity.RouterIP,
			PeerHash:       ph.GetPeerHash(),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.GetPeerTimestamp(),
			Nexthop:        nextHop,
			BaseAttributes: update.BaseAttributes,
		}
		if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
			// Last element in AS_PATH would be the AS of the origin
			prfx.OriginAS = ases[len(ases)-1]
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
				prfx.ESI = hexColon(esi[:], ESILength)
			}
			prfx.EthTag = e.GetEVPNTAG()
			if ip := e.GetEVPNIPLength(); ip != nil {
				prfx.IPLength = *ip
				gw := e.GetEVPNGWAddr()
				addr := e.GetEVPNIPAddr()
				// Address family comes from the byte length on the wire
				// (4 vs 16), not from the prefix length: an EVPN RT-5 IPv6
				// prefix can carry a length <= 32.
				if len(addr) == net.IPv4len || len(gw) == net.IPv4len {
					if addr != nil {
						prfx.IPAddress = net.IP(addr).To4().String()
					}
					if gw != nil {
						prfx.GWAddress = net.IP(gw).To4().String()
					}
				} else {
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
				if n := int(prfx.MACLength / 8); n > 0 {
					prfx.MAC = hexColon(e.GetEVPNMAC()[:], n)
				}
			}

			for _, l := range e.GetEVPNLabel() {
				prfx.Labels = append(prfx.Labels, l.Value)
				prfx.RawLabels = append(prfx.RawLabels, l.GetRawValue())
			}
			// Extract PMSI Tunnel for Type 3 routes (RFC 6514, RFC 7432 Section 7.3)
			if prfx.RouteType == 3 && update.BaseAttributes.PMSITunnel != nil {
				prfx.PMSITunnel = update.BaseAttributes.PMSITunnel
			}
			if f, err := ph.IsAdjRIBInPost(); err == nil {
				prfx.IsAdjRIBInPost = f
			}
			if f, err := ph.IsAdjRIBOutPost(); err == nil {
				prfx.IsAdjRIBOutPost = f
			}
			if f, err := ph.IsAdjRIBOut(); err == nil {
				prfx.IsAdjRIBOut = f
			}
			if f, err := ph.IsLocRIB(); err == nil {
				prfx.IsLocRIB = f
			}
			if f, err := ph.IsLocRIBFiltered(); err == nil {
				prfx.IsLocRIBFiltered = f
			}
			// RFC 9069: Set TableName for LocRIB peers
			if prfx.IsLocRIB {
				prfx.TableName = p.GetTableName(ph.GetPeerBGPIDString(), ph.GetPeerDistinguisherString())
			}
		}
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}

// hexColon returns the first n octets of b as two lowercase hex digits each,
// separated by colons, as an ESI or a MAC address is written.
func hexColon(b []byte, n int) string {
	if n <= 0 {
		return ""
	}
	const digits = "0123456789abcdef"
	s := make([]byte, 0, 3*n-1)
	for i := 0; i < n; i++ {
		if i > 0 {
			s = append(s, ':')
		}
		s = append(s, digits[b[i]>>4], digits[b[i]&0x0f])
	}
	return string(s)
}
