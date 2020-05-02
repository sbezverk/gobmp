package sr

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// AdjacencySIDTLV defines Prefix SID TLV Object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.2.1
type AdjacencySIDTLV struct {
	Flags  uint8  `json:"flags,omitempty"`
	Weight uint8  `json:"weight"`
	SID    []byte `json:"sid,omitempty"`
}

// UnmarshalAdjacencySIDTLV builds Adjacency SID TLV Object
func UnmarshalAdjacencySIDTLV(b []byte) (*AdjacencySIDTLV, error) {
	glog.V(6).Infof("Adjacency SID Raw: %s", tools.MessageHex(b))
	asid := AdjacencySIDTLV{}
	p := 0
	asid.Flags = b[p]
	p++
	asid.Weight = b[p]
	p++
	// SID length would be Length of b - Flags 1 byte - Weight 1 byte - 2 bytes Reserved
	sl := len(b) - 4
	asid.SID = make([]byte, len(b)-4)
	p += 2
	copy(asid.SID, b[p:p+sl])

	return &asid, nil
}
