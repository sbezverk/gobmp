package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LocatorTLV defines SRv6 Locator TLV object
// No RFC yet
type LocatorTLV struct {
	Flag      uint8
	Algorithm uint8
	Reserved  uint16
	Metric    uint32
	SubTLV    []SubTLV
}

func (loc *LocatorTLV) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += tools.AddLevel(l)
	s += "SRv6 Locator TLV:" + "\n"
	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Flag: %02x\n", loc.Flag)
	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Algorithm: %d\n", loc.Algorithm)
	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Metric: %d\n", loc.Metric)
	if loc.SubTLV != nil {
		for _, stlv := range loc.SubTLV {
			s += stlv.String(l + 2)
		}
	}

	return s
}

// UnmarshalSRv6LocatorTLV builds SRv6 Locator TLV object
func UnmarshalSRv6LocatorTLV(b []byte) (*LocatorTLV, error) {
	glog.V(6).Infof("SRv6 Locator TLV Raw: %s", tools.MessageHex(b))
	loc := LocatorTLV{}
	p := 0
	loc.Flag = b[p]
	p++
	loc.Algorithm = b[p]
	p++
	// Skip reserved byte
	p += 2
	loc.Metric = binary.BigEndian.Uint32(b[p : p+4])
	p += 4

	if len(b) > p {
		stlvs, err := UnmarshalSRv6SubTLV(b[p:])
		if err != nil {
			return nil, err
		}
		loc.SubTLV = stlvs
	}

	return &loc, nil
}
