package message

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// unicast process nlri 14 afi 1/2 safi 1 messages and generates UnicastPrefix messages
func (p *producer) flowspec(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]*Flowspec, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	fsnlri, err := nlri.GetFlowspecNLRI()
	if err != nil {
		return nil, err
	}
	fs := &Flowspec{
		Action:         operation,
		RouterHash:     p.speakerHash,
		RouterIP:       p.speakerIP,
		PeerHash:       ph.GetPeerHash(),
		PeerASN:        ph.PeerAS,
		Timestamp:      ph.GetPeerTimestamp(),
		BaseAttributes: update.BaseAttributes,
	}
	for _, f := range fsnlri.Spec {
		s, _ := f.MarshalJSON()
		glog.Infof("><SB> %s", string(s))
	}
	// for _, e := range u.NLRI {
	// 	prfx := UnicastPrefix{
	// 		Action:         operation,
	// 		RouterHash:     p.speakerHash,
	// 		RouterIP:       p.speakerIP,
	// 		PeerHash:       ph.GetPeerHash(),
	// 		PeerASN:        ph.PeerAS,
	// 		Timestamp:      ph.GetPeerTimestamp(),
	// 		PrefixLen:      int32(e.Length),
	// 		PathID:         int32(e.PathID),
	// 		BaseAttributes: update.BaseAttributes,
	// 	}
	// 	if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
	// 		// Last element in AS_PATH would be the AS of the origin
	// 		prfx.OriginAS = int32(ases[len(ases)-1])
	// 	}
	// 	if ph.FlagV {
	// 		// Peer is IPv6
	// 		prfx.PeerIP = net.IP(ph.PeerAddress).To16().String()
	// 	} else {
	// 		// Peer is IPv4
	// 		prfx.PeerIP = net.IP(ph.PeerAddress[12:]).To4().String()
	// 	}
	// 	prfx.Nexthop = nlri.GetNextHop()
	// 	if nlri.IsIPv6NLRI() {
	// 		// IPv6 specific conversions
	// 		prfx.IsIPv4 = false
	// 		prfx.IsNexthopIPv4 = false
	// 		a := make([]byte, 16)
	// 		copy(a, e.Prefix)
	// 		prfx.Prefix = net.IP(a).To16().String()
	// 	} else {
	// 		// IPv4 specific conversions
	// 		prfx.IsIPv4 = true
	// 		prfx.IsNexthopIPv4 = true
	// 		a := make([]byte, 4)
	// 		copy(a, e.Prefix)
	// 		prfx.Prefix = net.IP(a).To4().String()
	// 	}
	// 	if label {
	// 		for _, l := range e.Label {
	// 			prfx.Labels = append(prfx.Labels, l.Value)
	// 		}
	// 		// Some Label Unicast may carry BGP Attribute 40 (Prefix SID)
	// 		if psid, err := update.GetAttrPrefixSID(); err == nil {
	// 			prfx.PrefixSID = psid
	// 		}
	// 	}
	// 	prfxs = append(prfxs, prfx)
	// }

	return []*Flowspec{fs}, nil
}
