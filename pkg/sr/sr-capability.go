package sr

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Capability defines SR Capability object
// https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-ls-segment-routing-ext/?include_text=1 Section 2.1.2
type Capability struct {
	Flags uint8
	TLV   []CapabilityTLV
}

// UnmarshalSRCapability builds SR Capability object
func UnmarshalSRCapability(b []byte) (*Capability, error) {
	glog.V(6).Infof("SR Capability Raw: %s", tools.MessageHex(b))
	cap := Capability{}
	p := 0
	cap.Flags = b[p]
	p++
	// Skip reserved byte
	p++
	tlvs, err := UnmarshalSRCapabilityTLV(b[p:])
	if err != nil {
		return nil, err
	}
	cap.TLV = tlvs

	return &cap, nil
}
