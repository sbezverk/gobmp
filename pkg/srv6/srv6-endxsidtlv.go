package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// EndXSIDTLV defines SRv6 End.X SID TLV object
// No RFC yet
type EndXSIDTLV struct {
	EndpointBehavior uint16
	Flag             uint8
	Algorithm        uint8
	Weight           uint8
	Reserved         uint8
	SID              []byte
	SubTLV           []SubTLV
}

func (x *EndXSIDTLV) String() string {
	var s string

	s += "SRv6 End.X SID TLV:" + "\n"

	s += fmt.Sprintf("Endpoint Behavior: %d\n", x.EndpointBehavior)
	s += fmt.Sprintf("Flag: %02x\n", x.Flag)
	s += fmt.Sprintf("Algorithm: %d\n", x.Algorithm)
	s += fmt.Sprintf("Weight: %d\n", x.Weight)
	s += fmt.Sprintf("SID: %s\n", tools.MessageHex(x.SID))
	if x.SubTLV != nil {
		for _, stlv := range x.SubTLV {
			s += stlv.String()
		}
	}

	return s
}

// UnmarshalSRv6EndXSIDTLV builds SRv6 End.X SID TLV object
func UnmarshalSRv6EndXSIDTLV(b []byte) (*EndXSIDTLV, error) {
	glog.V(6).Infof("SRv6 End.X SID TLV Raw: %s", tools.MessageHex(b))
	endx := EndXSIDTLV{
		SID: make([]byte, 16),
	}
	p := 0
	endx.EndpointBehavior = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	endx.Flag = b[p]
	p++
	endx.Algorithm = b[p]
	p++
	endx.Weight = b[p]
	p++
	// Skip reserved byte
	p++
	copy(endx.SID, b[p:p+16])
	p += 16
	if len(b) > p {
		stlvs, err := UnmarshalSRv6SubTLV(b[p:])
		if err != nil {
			return nil, err
		}
		endx.SubTLV = stlvs
	}

	return &endx, nil
}
