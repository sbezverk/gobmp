package bgp

import (
	"encoding/binary"

	"github.com/golang/glog"
)

// AFISAFI identifies an address family without collapsing families that share
// an output message type, such as IPv4, IPv6, and VPN FlowSpec.
type AFISAFI struct {
	AFI  uint16
	SAFI uint8
}

// AddPathModes returns the advertised RFC 7911 Send/Receive mode for each
// AFI/SAFI: 1 = receive, 2 = send, 3 = both. Unsupported modes are ignored.
// Unlike AddPathCapability, this preserves direction and exact family identity.
func (o *OpenMessage) AddPathModes() map[AFISAFI]uint8 {
	modes := make(map[AFISAFI]uint8)
	if o == nil {
		return modes
	}
	for _, capability := range o.Capabilities[69] {
		if capability == nil || len(capability.Value) == 0 || len(capability.Value)%4 != 0 {
			glog.Errorf("invalid ADD-PATH capability: expected one or more 4-byte tuples")
			continue
		}
		for p := 0; p < len(capability.Value); p += 4 {
			mode := capability.Value[p+3]
			if mode < 1 || mode > 3 {
				continue
			}
			family := AFISAFI{
				AFI:  binary.BigEndian.Uint16(capability.Value[p : p+2]),
				SAFI: capability.Value[p+2],
			}
			modes[family] = mode
		}
	}
	return modes
}
