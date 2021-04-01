package sr

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

type PeerFlags struct {
	VFlag bool `json:"v_flag"`
	LFlag bool `json:"l_flag"`
	BFlag bool `json:"b_flag"`
	PFlag bool `json:"p_flag"`
}

func UnmarshalPeerFlags(b []byte) (*PeerFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal SR Peer Flags")
	}
	return &PeerFlags{
		VFlag: b[0]&0x80 == 0x80,
		LFlag: b[0]&0x40 == 0x40,
		BFlag: b[0]&0x20 == 0x20,
		PFlag: b[0]&0x10 == 0x10,
	}, nil
}

// PeerSID defines Peer SID TLV Object
// https://datatracker.ietf.org/doc/draft-ietf-idr-bgpls-segment-routing-epe Section 4
type PeerSID struct {
	Flags  *PeerFlags `json:"flags"`
	Weight uint8      `json:"weight"`
	SID    []byte     `json:"prefix_sid,omitempty"`
}

// UnmarshalPeerSID builds PeerSID TLV Object
func UnmarshalPeerSID(b []byte) (*PeerSID, error) {
	if glog.V(6) {
		glog.Infof("Peer SID TLV Raw: %s", tools.MessageHex(b))
	}
	psid := PeerSID{}
	p := 0
	f, err := UnmarshalPeerFlags(b[p : p+1])
	if err != nil {
		return nil, err
	}
	psid.Flags = f
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
