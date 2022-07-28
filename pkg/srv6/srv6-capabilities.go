package srv6

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// CapabilityTLV defines SRv6 Capability TLV object
// No RFC yet
type CapabilityTLV struct {
	OFlag bool `json:"o_flag"`
}

// UnmarshalSRv6CapabilityTLV builds SRv6 Capability TLV object
func UnmarshalSRv6CapabilityTLV(b []byte) (*CapabilityTLV, error) {
	if glog.V(6) {
		glog.Infof("SRv6 Capability TLV Raw: %s", tools.MessageHex(b))
	}
	cap := CapabilityTLV{}
	p := 0
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to decde SRv6 Capability TLV")
	}
	cap.OFlag = b[p]&0x40 == 0x40

	return &cap, nil
}
