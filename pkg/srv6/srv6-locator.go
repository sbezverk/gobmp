package srv6

import (
	"encoding/binary"

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
