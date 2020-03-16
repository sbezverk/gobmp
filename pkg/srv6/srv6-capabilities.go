package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// CapabilityTLV defines SRv6 Capability TLV object
// No RFC yet
type CapabilityTLV struct {
	Flag     uint16
	Reserved uint16
}

func (cap *CapabilityTLV) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += internal.AddLevel(l)
	s += "SRv6 Capability TLV:" + "\n"
	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("Flag: %02x\n", cap.Flag)

	return s
}

// UnmarshalSRv6CapabilityTLV builds SRv6 Capability TLV object
func UnmarshalSRv6CapabilityTLV(b []byte) (*CapabilityTLV, error) {
	glog.V(6).Infof("SRv6 Capability TLV Raw: %s", internal.MessageHex(b))
	cap := CapabilityTLV{}
	p := 0
	cap.Flag = binary.BigEndian.Uint16(b[p : p+2])

	return &cap, nil
}
