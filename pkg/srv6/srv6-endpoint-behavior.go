package srv6

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// EndpointBehavior defines SRv6 Endpoint Behavior TLV object
// No RFC yet
type EndpointBehavior struct {
	EndpointBehavior uint16 `json:"endpoint_behavior"`
	Flag             uint8  `json:"flag"`
	Algorithm        uint8  `json:"algo"`
}

// UnmarshalSRv6EndpointBehaviorTLV builds SRv6 Endpoint Behavior TLV object
func UnmarshalSRv6EndpointBehaviorTLV(b []byte) (*EndpointBehavior, error) {
	if glog.V(6) {
		glog.Infof("SRv6 End.X SID TLV Raw: %s", tools.MessageHex(b))
	}
	e := EndpointBehavior{}
	p := 0
	e.EndpointBehavior = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	e.Flag = b[p]
	p++
	e.Algorithm = b[p]

	return &e, nil
}
