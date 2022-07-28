package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// LocatorFlags defines a structure for SRv6 Locator's flags
// https://tools.ietf.org/html/draft-ietf-idr-bgpls-srv6-ext-07#section-5.1
type LocatorFlags struct {
	DFlag bool `json:"d_flag"`
}

// UnmarshalLocatorFlags builds a new SRv6 Locator's flags object
func UnmarshalLocatorFlags(b []byte) (*LocatorFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal SRv6 Locator Flags")
	}
	return &LocatorFlags{
		DFlag: b[0]&0x80 == 0x80,
	}, nil
}

// LocatorTLV defines SRv6 Locator TLV object
// No RFC yet
type LocatorTLV struct {
	Flag      *LocatorFlags  `json:"flags,omitempty"`
	Algorithm uint8          `json:"algo"`
	Metric    uint32         `json:"metric"`
	SubTLV    []*base.SubTLV `json:"sub_tlvs,omitempty"`
}

// UnmarshalSRv6LocatorTLV builds a SRv6 Locator object
func UnmarshalSRv6LocatorTLV(b []byte) (*LocatorTLV, error) {
	if glog.V(6) {
		glog.Infof("SRv6 Locator TLV Raw: %s", tools.MessageHex(b))
	}
	p := 0
	loc := LocatorTLV{}
	f, err := UnmarshalLocatorFlags(b[p : p+1])
	if err != nil {
		return nil, err
	}
	loc.Flag = f
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
		if len(stlvs) != 0 {
			loc.SubTLV = stlvs
		}
	}

	return &loc, nil
}
