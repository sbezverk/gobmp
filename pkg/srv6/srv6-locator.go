package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LocatorTLV defines SRv6 Locator TLV object
// No RFC yet
type LocatorTLV struct {
	Flag      uint8          `json:"flag"`
	Algorithm uint8          `json:"algo"`
	Metric    uint32         `json:"metric,omitempty"`
	SubTLV    []*base.SubTLV `json:"sub_tlvs,omitempty"`
}

// UnmarshalSRv6LocatorTLV builds a SRv6 Locator object
func UnmarshalSRv6LocatorTLV(b []byte) (*LocatorTLV, error) {
	glog.V(6).Infof("SRv6 Locator TLV Raw: %s", tools.MessageHex(b))
	p := 0
	loc := LocatorTLV{}
	loc.Flag = b[p]
	if p+1 > len(b) {
		return nil, fmt.Errorf("invalid input %s", tools.MessageHex(b))
	}
	p++
	loc.Algorithm = b[p]
	if p+1 > len(b) {
		return nil, fmt.Errorf("invalid input %s", tools.MessageHex(b))
	}
	p++
	// Skip reserved byte
	if p+2 > len(b) {
		return nil, fmt.Errorf("invalid input %s", tools.MessageHex(b))
	}
	p += 2
	if p+4 > len(b) {
		return nil, fmt.Errorf("invalid input %s", tools.MessageHex(b))
	}
	loc.Metric = binary.BigEndian.Uint32(b[p : p+4])
	p += 4

	if len(b) > p {
		stlvs, err := base.UnmarshalSubTLV(b[p:])
		if err != nil {
			return nil, err
		}
		loc.SubTLV = stlvs
	}

	return &loc, nil
}
