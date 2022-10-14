package message

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/srpolicy"
)

// evpn process MP_REACH_NLRI AFI 25 SAFI 70 update message and returns
// EVPN prefix object.
func (p *producer) srpolicy(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]*SRPolicy, error) {
	sr, err := nlri.GetNLRI73()
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
	prfx := SRPolicy{
		Action:         operation,
		RouterHash:     p.speakerHash,
		RouterIP:       p.speakerIP,
		PeerType:       uint8(ph.PeerType),
		PeerHash:       ph.GetPeerHash(),
		PeerASN:        ph.PeerAS,
		Timestamp:      ph.GetPeerTimestamp(),
		Nexthop:        nlri.GetNextHop(),
		BaseAttributes: update.BaseAttributes,
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
	if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
		// Last element in AS_PATH would be the AS of the origin
		prfx.OriginAS = int32(ases[len(ases)-1])
	}
	prfx.PeerIP = ph.GetPeerAddrString()
	prfx.IsIPv4 = true
	prfx.IsNexthopIPv4 = true
	if nlri.IsIPv6NLRI() {
		prfx.IsIPv4 = false
		prfx.IsNexthopIPv4 = false
	}
	prfx.Distinguisher = sr.Distinguisher
	prfx.Color = sr.Color
	prfx.Endpoint = make([]byte, len(sr.Endpoint))
	copy(prfx.Endpoint, sr.Endpoint)
	// Getting SR Policy TLV encapsulated into Tunnel Encapsulate Attribute of type 15
	tlv, err := srpolicy.UnmarshalSRPolicyTLV(update.BaseAttributes.TunnelEncapAttr)
	if err != nil {
		return nil, err
	}
	if tlv != nil {
		prfx.PolicyName = tlv.Name
		if tlv.BindingSID != nil {
			prfx.BSID = tlv.BindingSID
		}
		if tlv.Preference != nil {
			prfx.Preference = tlv.Preference
		}
		prfx.Priority = tlv.Priority
		prfx.PolicyPathName = tlv.PathName
		if tlv.ENLP != nil {
			prfx.ENLP = tlv.ENLP
		}
		if len(tlv.SegmentList) != 0 {
			prfx.SegmentList = tlv.SegmentList
		}
	}

	return []*SRPolicy{&prfx}, nil
}
