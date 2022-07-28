package sr

import (
	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// LocalBlock defines SR Local Block TLV object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.1.4
type LocalBlock struct {
	Flags uint8           `json:"flags"`
	TLV   []LocalBlockTLV `json:"subranges,omitempty"`
}

// UnmarshalSRLocalBlock builds SR Local Block object
func UnmarshalSRLocalBlock(b []byte) (*LocalBlock, error) {
	if glog.V(6) {
		glog.Infof("SR Local BLock Raw: %s", tools.MessageHex(b))
	}
	lb := LocalBlock{}
	p := 0
	lb.Flags = b[p]
	p++
	// Skip reserved byte
	p++
	tlvs, err := UnmarshalSRLocalBlockTLV(b[p:])
	if err != nil {
		return nil, err
	}
	lb.TLV = tlvs

	return &lb, nil
}
