package sr

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// AdjacencySIDTLV defines Prefix SID TLV Object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.2.1
type AdjacencySIDTLV struct {
	Flags  uint8  `json:"flags,omitempty"`
	Weight uint8  `json:"weight"`
	SID    uint32 `json:"sid,omitempty"`
}

// UnmarshalAdjacencySIDTLV builds Adjacency SID TLV Object
func UnmarshalAdjacencySIDTLV(b []byte) (*AdjacencySIDTLV, error) {
	if glog.V(6) {
		glog.Infof("Adjacency SID Raw: %s", tools.MessageHex(b))
	}
	asid := AdjacencySIDTLV{}
	p := 0
	asid.Flags = b[p]
	p++
	asid.Weight = b[p]
	p++
	// SID length would be Length of b - Flags 1 byte - Weight 1 byte - 2 bytes Reserved
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
	asid.SID = binary.BigEndian.Uint32(s)

	return &asid, nil
}
