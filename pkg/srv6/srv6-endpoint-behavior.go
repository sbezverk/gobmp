package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// EndpointBehavior defines SRv6 Endpoint Behavior TLV object
// No RFC yet
type EndpointBehavior struct {
	EndpointBehavior uint16
	Flag             uint8
	Algorithm        uint8
}

func (e *EndpointBehavior) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += tools.AddLevel(l)
	s += "SRv6 End.X SID TLV:" + "\n"

	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Endpoint Behavior: %d\n", e.EndpointBehavior)
	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Flag: %02x\n", e.Flag)
	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Algorithm: %d\n", e.Algorithm)

	return s
}

// MarshalJSON defines a method to Marshal SRv6 Endpoint Behavior TLV object into JSON format
func (e *EndpointBehavior) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"endpointBehavior\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", e.EndpointBehavior))...)
	jsonData = append(jsonData, []byte("\"flag\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", e.Flag))...)
	jsonData = append(jsonData, []byte("\"algorithm\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d", e.Algorithm))...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalSRv6EndpointBehaviorTLV builds SRv6 Endpoint Behavior TLV object
func UnmarshalSRv6EndpointBehaviorTLV(b []byte) (*EndpointBehavior, error) {
	glog.V(6).Infof("SRv6 End.X SID TLV Raw: %s", tools.MessageHex(b))
	e := EndpointBehavior{}
	p := 0
	e.EndpointBehavior = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	e.Flag = b[p]
	p++
	e.Algorithm = b[p]

	return &e, nil
}
