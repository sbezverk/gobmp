package bmp

import (
	"encoding/binary"
	"fmt"
)

// StatsReport defines BMP Stats message structure
type StatsReport struct {
	StatsCount int32
	StatsTLV   []InformationalTLV
}

// UnmarshalBMPStatsReportMessage builds BMP Stats Reports object
func UnmarshalBMPStatsReportMessage(b []byte) (*StatsReport, error) {
	sr := StatsReport{}
	p := 0
	l := int32(binary.BigEndian.Uint32(b[p : p+4]))
	if l > int32(len(b)) {
		return nil, fmt.Errorf("invalid length of Stats Report %d", l)
	}
	sr.StatsCount = l
	p += 4
	tlvs, err := UnmarshalTLV(b[p:])
	if err != nil {
		return nil, err
	}
	sr.StatsTLV = tlvs

	return &sr, nil
}
