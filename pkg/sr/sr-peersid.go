package sr

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// PeerFlags defines Flags structure for SR Peer SID object
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
	SID    uint32     `json:"sid,omitempty"`
}

func (p *PeerSID) String() string {
	s, _ := json.Marshal(p)
	return string(s)
}

// UnmarshalPeerSID builds PeerSID TLV Object
func UnmarshalPeerSID(b []byte) (*PeerSID, error) {
	if glog.V(6) {
		glog.Infof("Peer SID TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 7 && len(b) != 8 {
		return nil, fmt.Errorf("invalid length %d of data to decode peer sid tlv", len(b))
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
	p += 2
	l := len(b) - 4
	s := make([]byte, 4)
	switch l {
	case 3:
		if !psid.Flags.VFlag || !psid.Flags.LFlag {
			// When sid is 3 bytes, V and L flags MUST be set to "true", if not, error out
			return nil, fmt.Errorf("sid length is 3 bytes but V flag is NOT set to \"true\"")
		}
		copy(s[1:], b[p:p+3])
		// Since label uses only 20 bits for label, clear first 4 bits of s[1]
		s[1] &= 0x0f
	case 4:
		if psid.Flags.VFlag {
			// When sid is 4 bytes, V flag must NOT be set to "true", if not, error out
			return nil, fmt.Errorf("sid length is 4 bytes but V flag is set to \"true\"")
		}
		copy(s, b[p:p+4])
	default:
		return nil, fmt.Errorf("software bug in peer sid processing logic, byte slice: %s", tools.MessageHex(b))
	}
	psid.SID = binary.BigEndian.Uint32(s)

	return &psid, nil
}
