package message

import (
	"fmt"
	"net"

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

	if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
		// Last element in AS_PATH would be the AS of the origin
		fs.OriginAS = int32(ases[len(ases)-1])
	}
	if ph.FlagV {
		// Peer is IPv6
		fs.PeerIP = net.IP(ph.PeerAddress).To16().String()
	} else {
		// Peer is IPv4
		fs.PeerIP = net.IP(ph.PeerAddress[12:]).To4().String()
	}
	fs.Nexthop = nlri.GetNextHop()
	fs.Spec = fsnlri.Spec
	if nlri.IsIPv6NLRI() {
		// IPv6 specific conversions
		fs.IsIPv4 = false
	} else {
		// IPv4 specific conversions
		fs.IsIPv4 = true
	}
	if nlri.IsNextHopIPv6() {
		fs.IsNexthopIPv4 = false
	} else {
		fs.IsNexthopIPv4 = true
	}

	return []*Flowspec{fs}, nil
}
