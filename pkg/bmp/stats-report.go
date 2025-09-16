package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

type StatTLV struct {
	StatType   int16  `json:"stat_type"`
	StatLength int16  `json:"stat_length"`
	StatData   []byte `json:"stat_data"`
}

// UnmarshalTLV builds a slice of Informational TLVs
func UnmarshalStatTLV(b []byte) ([]StatTLV, error) {
	if glog.V(6) {
		glog.Infof("BMP Informational TLV Raw: %s", tools.MessageHex(b))
	}
	tlvs := make([]StatTLV, 0)
	for i := 0; i < len(b); {
		// Extracting TLV type 2 bytes
		t := int16(binary.BigEndian.Uint16(b[i : i+2]))
		// Extracting TLV length
		l := int16(binary.BigEndian.Uint16(b[i+2 : i+4]))
		if l > int16(len(b)-(i+4)) {
			return nil, fmt.Errorf("invalid tlv length %d", l)
		}
		v := b[i+4 : i+4+int(l)]
		tlvs = append(tlvs, StatTLV{
			StatType:   t,
			StatLength: l,
			StatData:   v,
		})
		i += 4 + int(l)
	}

	return tlvs, nil
}

// StatsReport defines BMP Stats message structure
type StatsReport struct {
	StatsCount int32
	StatsTLV   []StatTLV
}

// UnmarshalBMPStatsReportMessage builds BMP Stats Reports object
func UnmarshalBMPStatsReportMessage(b []byte) (*StatsReport, error) {
	if glog.V(6) {
		glog.Infof("BMP Stats Report Message Raw: %s", tools.MessageHex(b))
	}
	sr := StatsReport{}
	p := 0
	l := int32(binary.BigEndian.Uint32(b[p : p+4]))
	if l > int32(len(b)) {
		return nil, fmt.Errorf("invalid length of Stats Report %d", l)
	}
	sr.StatsCount = l
	p += 4
	tlvs, err := UnmarshalStatTLV(b[p:])
	if err != nil {
		return nil, err
	}
	sr.StatsTLV = tlvs

	return &sr, nil
}
