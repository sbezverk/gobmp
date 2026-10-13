package message

import (
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// unicast process nlri 14 afi 1/2 safi 1 messages and generates UnicastPrefix messages
func (p *producer) unicast(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update, label bool) ([]*UnicastPrefix, error) {
	var err error
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	prfxs := make([]*UnicastPrefix, 0)
	var u *base.MPNLRI
	if label {
		u, err = nlri.GetNLRILU()
		if err != nil {
			return nil, err
		}
	} else {
		u, err = nlri.GetNLRIUnicast()
		if err != nil {
			return nil, err
		}
	}
	// Check if Update carries any routes, if update comes with 0 routes, it is EoR message
	if len(u.NLRI) == 0 {
		prfx := &UnicastPrefix{
			Action:      operation,
			RouterHash:  ph.Identity.RouterHash,
			RouterIP:    ph.Identity.RouterIP,
			PeerHash:    ph.GetPeerHash(),
			RemoteBGPID: ph.GetPeerBGPIDString(),
			PeerIP:      ph.GetPeerAddrString(),
			PeerASN:     ph.PeerAS,
			Timestamp:   ph.GetPeerTimestamp(),
			PeerType:    uint8(ph.PeerType),
			IsEOR:       true,
			IsIPv4:      !nlri.IsIPv6NLRI(),
		}
		prfx.IsNexthopIPv4 = prfx.IsIPv4
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
		return []*UnicastPrefix{prfx}, nil
	}
	for _, e := range u.NLRI {
		prfx := &UnicastPrefix{
			Action:         operation,
			RouterHash:     ph.Identity.RouterHash,
			RouterIP:       ph.Identity.RouterIP,
			PeerType:       uint8(ph.PeerType),
			PeerHash:       ph.GetPeerHash(),
			RemoteBGPID:    ph.GetPeerBGPIDString(),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.GetPeerTimestamp(),
			PrefixLen:      int32(e.Length),
			PathID:         int32(e.PathID),
			BaseAttributes: update.BaseAttributes,
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
		if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
			// Last element in AS_PATH would be the AS of the origin
			prfx.OriginAS = ases[len(ases)-1]
		}
		prfx.PeerIP = ph.GetPeerAddrString()
		prfx.Nexthop = nlri.GetNextHop()
		if nlri.IsIPv6NLRI() {
			// IPv6 specific conversions
			prfx.IsIPv4 = false
			a := make([]byte, 16)
			copy(a, e.Prefix)
			prfx.Prefix = net.IP(a).To16().String()
		} else {
			// IPv4 specific conversions
			prfx.IsIPv4 = true
			a := make([]byte, 4)
			copy(a, e.Prefix)
			prfx.Prefix = net.IP(a).To4().String()
			// Cap IPv4 prefix lengths at 32 bits
			if prfx.PrefixLen > 32 {
				if glog.V(6) {
					glog.Warningf("Capping excessive IPv4 prefix length %d to 32 for prefix %s",
						prfx.PrefixLen, prfx.Prefix)
				}
				prfx.PrefixLen = 32
			}
		}
		// Next hop family is determined by the Length of Next Hop field, not
		// the NLRI AFI (RFC 8950 §3, updating RFC 4760 §3): an AFI 1 route may
		// carry a 16-byte next hop, and a 6PE (RFC 4798 §2) AFI 2 route carries
		// an IPv4-mapped ::ffff: next hop. MP_UNREACH_NLRI has no next hop field,
		// so fall back to the NLRI's own family (matches l3-vpn.go).
		if prfx.Nexthop == "" {
			prfx.IsNexthopIPv4 = prfx.IsIPv4
		} else {
			prfx.IsNexthopIPv4 = !nlri.IsNextHopIPv6()
		}
		if label {
			for _, l := range e.Label {
				prfx.Labels = append(prfx.Labels, l.Value)
			}
			// Some Label Unicast may carry BGP Attribute 40 (Prefix SID)
			if psid, err := update.GetAttrPrefixSID(); err == nil {
				prfx.PrefixSID = psid
			}
		}
		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}
