package sr

import (
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Capability defines SR Capability object
// https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-ls-segment-routing-ext/?include_text=1 Section 2.1.2
type Capability struct {
	Flags uint8
	TLV   []CapabilityTLV
}

// MarshalJSON defines a method to Marshal SR Capabilities TLV object into JSON format
func (cap *Capability) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"flags\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", cap.Flags))...)
	jsonData = append(jsonData, []byte("\"tlvs\":")...)
	for i, t := range cap.TLV {
		jsonData = append(jsonData, '[')
		b, err := json.Marshal(&t)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
		if i < len(cap.TLV)-1 {
			jsonData = append(jsonData, ',')
		}
		jsonData = append(jsonData, ']')
	}
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalSRCapability builds SR Capability object
func UnmarshalSRCapability(b []byte) (*Capability, error) {
	glog.V(5).Infof("SR Capability Raw: %s", tools.MessageHex(b))
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
