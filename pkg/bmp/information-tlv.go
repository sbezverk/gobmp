package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// InformationalTLV defines Informational TLV per rfc7854
type InformationalTLV struct {
	InformationType   uint16
	InformationLength uint16
	Information       []byte
}

// UnmarshalTLV builds a slice of Informational TLVs
func UnmarshalTLV(b []byte) ([]InformationalTLV, error) {
	if glog.V(6) {
		glog.Infof("BMP Informational TLV Raw: %s", tools.MessageHex(b))
	}
	tlvs := make([]InformationalTLV, 0)
	if len(b) == 0 {
		return tlvs, nil
	}
	for i := 0; i < len(b); {
		// Extracting TLV type 2 bytes
		if i+2 > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode TLV type, need 2 bytes, have %d", len(b)-i)
		}
		t := binary.BigEndian.Uint16(b[i : i+2])
		// Extracting TLV length
		if i+4 > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode TLV length, need 2 bytes, have %d", len(b)-(i+2))
		}
		l := binary.BigEndian.Uint16(b[i+2 : i+4])
		if int(l) > len(b)-(i+4) {
			return nil, fmt.Errorf("not enough bytes to decode TLV value, need %d bytes, have %d", l, len(b)-(i+4))
		}
		v := b[i+4 : i+4+int(l)]
		tlvs = append(tlvs, InformationalTLV{
			InformationType:   t,
			InformationLength: l,
			Information:       v,
		})
		i += 4 + int(l)
	}

	return tlvs, nil
}
