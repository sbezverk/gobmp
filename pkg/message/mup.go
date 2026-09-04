package message

import (
	"errors"
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/mup"
)

// mup processes MP_REACH_NLRI/MP_UNREACH_NLRI AFI 1/2 SAFI 85 (BGP-MUP) update
// message and returns MUP prefix objects.
func (p *producer) mup(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]MUPPrefix, error) {
	var operation string
	switch op {
	case AddPrefix:
		operation = "add"
	case DelPrefix:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	route, err := nlri.GetNLRIMUP()
	if errors.Is(err, mup.ErrEmptyNLRI) {
		// RFC 4724 §2 encodes End-of-RIB as an UPDATE carrying only an
		// MP_UNREACH_NLRI with no withdrawn routes. An empty MP_REACH_NLRI is
		// not one and must not be published as an EoR.
		if op != DelPrefix {
			return nil, fmt.Errorf("empty MUP NLRI in MP_REACH_NLRI")
		}
		prfx := MUPPrefix{
			Action:      "del",
			RouterHash:  ph.Identity.RouterHash,
			RouterIP:    ph.Identity.RouterIP,
			PeerHash:    ph.GetPeerHash(),
			RemoteBGPID: ph.GetPeerBGPIDString(),
			PeerASN:     ph.PeerAS,
			Timestamp:   ph.GetPeerTimestamp(),
			PeerType:    uint8(ph.PeerType),
			IsEOR:       true,
			IsIPv4:      !nlri.IsIPv6NLRI(),
		}
		prfx.IsNexthopIPv4 = prfx.IsIPv4
		prfx.PeerIP = ph.GetPeerAddrString()
		setMUPRIBFlags(p, &prfx, ph)
		return []MUPPrefix{prfx}, nil
	}
	if err != nil {
		return nil, err
	}

	prfxs := make([]MUPPrefix, 0, len(route.Route))
	for _, e := range route.Route {
		prfx := MUPPrefix{
			Action:         operation,
			RouterHash:     ph.Identity.RouterHash,
			RouterIP:       ph.Identity.RouterIP,
			PeerHash:       ph.GetPeerHash(),
			RemoteBGPID:    ph.GetPeerBGPIDString(),
			PeerIP:         ph.GetPeerAddrString(),
			PeerType:       uint8(ph.PeerType),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.GetPeerTimestamp(),
			Nexthop:        nlri.GetNextHop(),
			BaseAttributes: update.BaseAttributes,
			IsIPv4:         !nlri.IsIPv6NLRI(),
			PathID:         int32(e.PathID),
			ArchType:       e.GetMUPArchitectureType(),
			RouteType:      e.GetMUPRouteType(),
		}
		// MP_UNREACH_NLRI carries no next hop, so a withdrawal follows the
		// address family of the NLRI like the End-of-RIB path does.
		if prfx.Nexthop == "" {
			prfx.IsNexthopIPv4 = prfx.IsIPv4
		} else {
			prfx.IsNexthopIPv4 = !nlri.IsNextHopIPv6()
		}
		if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
			// Last element in AS_PATH would be the AS of the origin
			prfx.OriginAS = ases[len(ases)-1]
		}
		if rd := e.GetMUPRD(); rd != nil {
			prfx.VPNRD = rd.String()
			prfx.VPNRDType = rd.Type
		}
		// ISD and DSD routes carry their SRv6 SID and endpoint behavior in the
		// Prefix-SID attribute, the same way L3VPN routes do.
		if psid, err := update.GetAttrPrefixSID(); err == nil {
			prfx.PrefixSID = psid
		}
		switch r := e.GetRouteTypeSpec().(type) {
		case *mup.ISDRoute:
			prfx.Prefix = net.IP(r.Prefix).String()
			prfx.PrefixLen = r.PrefixLength
		case *mup.DSDRoute:
			prfx.Address = net.IP(r.Address).String()
		case *mup.ST1Route:
			teid, qfi := r.TEID, r.QFI
			prfx.Prefix = net.IP(r.Prefix).String()
			prfx.PrefixLen = r.PrefixLength
			prfx.TEID = &teid
			prfx.QFI = &qfi
			prfx.EndpointAddress = net.IP(r.EndpointAddress).String()
			prfx.EndpointLen = r.EndpointAddressLength
			if r.SourceAddress != nil {
				prfx.SourceAddress = net.IP(r.SourceAddress).String()
			}
		case *mup.ST2Route:
			if r.TEID != nil {
				teid := *r.TEID
				prfx.TEID = &teid
			}
			prfx.EndpointAddress = net.IP(r.EndpointAddress).String()
			prfx.EndpointLen = r.EndpointLength
			prfx.TLVs = r.TLVs
			// The 3gpp-5g Session Parameters TLV carries the session the
			// route was transformed from, it is the only place a Type 2 ST
			// route reports a QFI.
			for _, t := range r.TLVs {
				if _, qfi, ok := t.SessionParameters(); ok {
					prfx.QFI = &qfi
					break
				}
			}
		}
		setMUPRIBFlags(p, &prfx, ph)
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}

// setMUPRIBFlags assigns the RIB flags carried by the Per Peer Header
func setMUPRIBFlags(p *producer, prfx *MUPPrefix, ph *bmp.PerPeerHeader) {
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
