package sr

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PeerSID defines Peer SID TLV Object
// https://datatracker.ietf.org/doc/draft-ietf-idr-bgpls-segment-routing-epe Section 4
type PeerSID struct {
	FlagV  bool   `json:"v_flag"`
	FlagL  bool   `json:"l_flag"`
	FlagB  bool   `json:"b_flag"`
	FlagP  bool   `json:"p_flag"`
	Weight uint8  `json:"weight"`
	SID    []byte `json:"prefix_sid,omitempty"`
}

// UnmarshalPeerSID builds PeerSID TLV Object
func UnmarshalPeerSID(b []byte) (*PeerSID, error) {
	if glog.V(6) {
		glog.Infof("Peer SID TLV Raw: %s", tools.MessageHex(b))
	}
	psid := PeerSID{}
	p := 0
	psid.FlagV = b[p]&0x80 == 0x80
	psid.FlagL = b[p]&0x40 == 0x40
	psid.FlagB = b[p]&0x20 == 0x20
	psid.FlagP = b[p]&0x10 == 0x10
	p++
	psid.Weight = b[p]
	p++
	// SID length would be Length of b - Flags 1 byte - Weight 1 byte - 2 bytes Reserved
	sl := len(b) - 4
	psid.SID = make([]byte, len(b)-4)
	p += 2
	copy(psid.SID, b[p:p+sl])

	return &psid, nil
}
