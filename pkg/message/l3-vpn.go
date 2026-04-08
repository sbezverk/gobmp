package message

import (
	"errors"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/l3vpn"
)

// l3vpn process MP_REACH_NLRI AFI 1/2 SAFI 128 update message and returns
// L3VPN prefix object.
func (p *producer) l3vpn(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]L3VPNPrefix, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	nlril3vpn, err := nlri.GetNLRIL3VPN()
	if errors.Is(err, l3vpn.ErrEmptyNLRI) {
		// Empty NLRI signals End-of-RIB per RFC 4724 §2 and is encoded as a withdrawal.
		prfx := L3VPNPrefix{
			Action:     "del",
			RouterHash: p.speakerHash,
			RouterIP:   p.speakerIP,
			PeerHash:   ph.GetPeerHash(),
			PeerASN:    ph.PeerAS,
			Timestamp:  ph.GetPeerTimestamp(),
			PeerType:   uint8(ph.PeerType),
			IsEOR:      true,
			IsIPv4:     !nlri.IsIPv6NLRI(),
		}
		prfx.IsNexthopIPv4 = prfx.IsIPv4
		prfx.PeerIP = ph.GetPeerAddrString()
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
		return []L3VPNPrefix{prfx}, nil
	}
	if err != nil {
		return nil, err
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
			prfx.OriginAS = ases[len(ases)-1]
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
		// Cap IPv4 prefix lengths at 32 bits
		if prfx.IsIPv4 && prfx.PrefixLen > 32 {
			if glog.V(6) {
				glog.Warningf("Capping excessive IPv4 prefix length %d to 32 for L3VPN prefix %s",
					prfx.PrefixLen, prfx.Prefix)
			}
			prfx.PrefixLen = 32
		}
		prfx.IsNexthopIPv4 = !nlri.IsNextHopIPv6()
		prfx.PeerIP = ph.GetPeerAddrString()
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
