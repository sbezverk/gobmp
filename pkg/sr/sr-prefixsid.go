package sr

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PrefixSIDTLV defines Prefix SID TLV Object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.3.1
type PrefixSIDTLV struct {
	Flags     uint8  `json:"flags,omitempty"`
	Algorithm uint8  `json:"algo"`
	SID       uint32 `json:"prefix_sid,omitempty"`
}

// OSPF Extensions for Segment Routing RFC 8665, Section 5
// 0  1  2  3  4  5  6  7
// +--+--+--+--+--+--+--+--+
// |  |NP|M |E |V |L |  |  |
// +--+--+--+--+--+--+--+--+
//IS-IS Extensions for Segment Routing RFC 8667 Section 2.1.1.
// 0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |R|N|P|E|V|L|   |
// +-+-+-+-+-+-+-+-+

// UnmarshalPrefixSIDTLV builds Prefix SID TLV Object
func UnmarshalPrefixSIDTLV(b []byte) (*PrefixSIDTLV, error) {
	if glog.V(6) {
		glog.Infof("Prefix SID TLV Raw: %s", tools.MessageHex(b))
	}
	psid := PrefixSIDTLV{}
	p := 0
	psid.Flags = b[p]
	p++
	psid.Algorithm = b[p]
	p++
	// SID length would be Length of b - Flags 1 byte - Algorithm 1 byte - 2 bytes Reserved
	// If length of Prefix SID TLV 7 bytes, then SID is 20 bits label, if 8 bytes then SID is 4 bytes index
	p += 2
	s := make([]byte, 4)
	switch len(b) {
	case 7:
		copy(s[1:], b[p:p+3])
	case 8:
		copy(s, b[p:p+4])
	default:
		return nil, fmt.Errorf("invalid length %d for Prefix SID TLV", len(b))
	}
	psid.SID = binary.BigEndian.Uint32(s)

	return &psid, nil
}
