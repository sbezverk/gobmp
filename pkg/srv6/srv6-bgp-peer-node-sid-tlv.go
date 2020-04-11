package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// BGPPeerNodeSID defines SRv6 BGP Peer Node SID TLV object
// No RFC yet
type BGPPeerNodeSID struct {
	Flag    uint8
	Weight  uint8
	PeerASN uint32
	PeerID  []byte
}

func (b *BGPPeerNodeSID) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += tools.AddLevel(l)
	s += "SRv6 BGP Peer Node SID TLV:" + "\n"

	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Flag: %02x\n", b.Flag)
	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Weight: %d\n", b.Weight)
	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Peer ASN: %d\n", b.PeerASN)
	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Peer ID: %s\n", tools.MessageHex(b.PeerID))

	return s
}

// UnmarshalSRv6BGPPeerNodeSIDTLV builds SRv6 BGP Peer Node SID TLV object
func UnmarshalSRv6BGPPeerNodeSIDTLV(b []byte) (*BGPPeerNodeSID, error) {
	glog.V(6).Infof("SRv6 BGP Peer Node SID TLV Raw: %s", tools.MessageHex(b))
	bgp := BGPPeerNodeSID{}
	p := 0
	bgp.Flag = b[p]
	p++
	bgp.Weight = b[p]
	// Skip reserved 2 bytes
	p += 2
	bgp.PeerASN = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	bgp.PeerID = make([]byte, 4)
	copy(bgp.PeerID, b[p:p+4])

	return &bgp, nil
}
