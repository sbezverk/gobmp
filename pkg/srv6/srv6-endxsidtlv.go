package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
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

func (x *EndXSIDTLV) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += internal.AddLevel(l)
	s += "SRv6 End.X SID TLV:" + "\n"

	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("Endpoint Behavior: %d\n", x.EndpointBehavior)
	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("Flag: %02x\n", x.Flag)
	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("Algorithm: %d\n", x.Algorithm)
	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("Weight: %d\n", x.Weight)
	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("SID: %s\n", internal.MessageHex(x.SID))
	if x.SubTLV != nil {
		for _, stlv := range x.SubTLV {
			s += stlv.String(l + 2)
		}
	}

	return s
}

// UnmarshalSRv6EndXSIDTLV builds SRv6 End.X SID TLV object
func UnmarshalSRv6EndXSIDTLV(b []byte) (*EndXSIDTLV, error) {
	glog.V(6).Infof("SRv6 End.XS ID TLV Raw: %s", internal.MessageHex(b))
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
