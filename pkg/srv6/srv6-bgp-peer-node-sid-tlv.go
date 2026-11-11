package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// BGPPeerNodeFlags defines Flags structure for BGP Peer Node SID object
type BGPPeerNodeFlags struct {
	BFlag bool `json:"b_flag"`
	SFlag bool `json:"s_flag"`
	PFlag bool `json:"p_flag"`
}

func UnmarshalBGPPeerNodeFlags(b []byte) (*BGPPeerNodeFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal BGP Peer Node SID Flags")
	}
	return &BGPPeerNodeFlags{
		BFlag: b[0]&0x80 == 0x80,
		SFlag: b[0]&0x40 == 0x40,
		PFlag: b[0]&0x20 == 0x20,
	}, nil
}

// bgpPeerNodeSIDLen is the fixed length of the SRv6 BGP PeerNode SID TLV value (RFC 9514 §7.2).
const bgpPeerNodeSIDLen = 12

// BGPPeerNodeSID defines SRv6 BGP PeerNode SID TLV object (RFC 9514 §7.2)
type BGPPeerNodeSID struct {
	Flags   *BGPPeerNodeFlags `json:"flags"`
	Weight  uint8             `json:"weight"`
	PeerASN uint32            `json:"peer_asn"`
	PeerID  []byte            `json:"peer_id"`
}

// UnmarshalSRv6BGPPeerNodeSIDTLV builds SRv6 BGP Peer Node SID TLV object
func UnmarshalSRv6BGPPeerNodeSIDTLV(b []byte) (*BGPPeerNodeSID, error) {
	if glog.V(6) {
		glog.Infof("SRv6 BGP Peer Node SID TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != bgpPeerNodeSIDLen {
		return nil, fmt.Errorf("srv6 BGP Peer Node SID TLV length must be %d bytes, have %d", bgpPeerNodeSIDLen, len(b))
	}
	bgp := BGPPeerNodeSID{}
	p := 0
	f, err := UnmarshalBGPPeerNodeFlags(b[p : p+1])
	if err != nil {
		return nil, err
	}
	bgp.Flags = f
	p++
	bgp.Weight = b[p]
	// Advance past weight byte and 2 reserved bytes
	p += 3
	bgp.PeerASN = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	bgp.PeerID = make([]byte, 4)
	copy(bgp.PeerID, b[p:p+4])

	return &bgp, nil
}
