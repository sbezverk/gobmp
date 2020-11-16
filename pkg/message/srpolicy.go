package message

import (
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/srpolicy"
)

// evpn process MP_REACH_NLRI AFI 25 SAFI 70 update message and returns
// EVPN prefix object.
func (p *producer) srpolicy(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]*SRPolicy, error) {
	glog.Infof("All attributes in evpn upate: %+v", update.GetAllAttributeID())
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
	prfx.Distinguisher = sr.Distinguisher
	prfx.Color = sr.Color
	prfx.Endpoint = make([]byte, len(sr.Endpoint))
	copy(prfx.Endpoint, sr.Endpoint)
	// Getting SR Policy TLV encapsulated into Tunnel Encapsulate Attribute of type 15
	tlv, err := srpolicy.UnmarshalSRPolicyTLV(update.BaseAttributes.TunnelEncapAttr)
	if err != nil {
		return nil, err
	}
	if tlv.Name != nil {
		prfx.PolicyName = tlv.Name.PolicyName
	}
	if tlv.BindingSID != nil {
		prfx.BSID = tlv.BindingSID
	}

	return []*SRPolicy{&prfx}, nil
}
