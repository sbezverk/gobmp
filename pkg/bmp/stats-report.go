package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// StatsReport defines BMP Stats message structure
type StatsReport struct {
	StatsCount uint32
	StatsTLV   []InformationalTLV
}

// UnmarshalBMPStatsReportMessage builds BMP Stats Reports object
func UnmarshalBMPStatsReportMessage(b []byte) (*StatsReport, error) {
	if glog.V(6) {
		glog.Infof("BMP Stats Report Message Raw: %s", tools.MessageHex(b))
	}
	sr := StatsReport{}
	p := 0
	if len(b) < 4 {
		return nil, fmt.Errorf("buffer too short for Stats Report: %d bytes", len(b))
	}
	count := binary.BigEndian.Uint32(b[p : p+4])
	// Each stat TLV requires at least 4 bytes (2 type + 2 length); validate count against remaining buffer
	if count > uint32(len(b)-4)/4 {
		return nil, fmt.Errorf("invalid Stats Report count %d exceeds available buffer", count)
	}
	sr.StatsCount = count
	p += 4
	tlvs, err := UnmarshalTLV(b[p:])
	if err != nil {
		return nil, err
	}
	sr.StatsTLV = tlvs

	return &sr, nil
}
