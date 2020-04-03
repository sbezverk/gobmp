package srv6

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PeerNodeSID defines SRv6 Peer Node SID
// https://datatracker.ietf.org/doc/draft-ietf-idr-bgpls-srv6-ext/?include_text=1 7.2
type PeerNodeSID struct {
	Flags     uint8  `json:"srv6_peer_node_flags,omitempty"`
	Weight    uint8  ` json:"srv6_peer_node_weight,omitempty"`
	PeerAS    uint32 `json:"srv6_peer_node_as,omitempty"`
	PeerBGPID uint32 `json:"srv6_peer_node_bgp_id,omitempty"`
}

// UnmarshalSRv6PeerNodeSID instantiate a SRv6 Peer Node SID Object
func UnmarshalSRv6PeerNodeSID(b []byte) (*PeerNodeSID, error) {
	glog.V(6).Infof("SRv6PeerNodeSID Raw: %s", tools.MessageHex(b))
	sid := PeerNodeSID{}
	sid.Flags = uint8(b[0])
	sid.Weight = b[1]
	sid.PeerAS = binary.BigEndian.Uint32(b[4:8])
	sid.PeerBGPID = binary.BigEndian.Uint32(b[8:12])

	return &sid, nil
}
