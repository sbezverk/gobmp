package srv6

import (
	"encoding/binary"

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
