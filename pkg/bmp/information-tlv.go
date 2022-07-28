package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// InformationalTLV defines Informational TLV per rfc7854
type InformationalTLV struct {
	InformationType   int16
	InformationLength int16
	Information       []byte
}

// UnmarshalTLV builds a slice of Informational TLVs
func UnmarshalTLV(b []byte) ([]InformationalTLV, error) {
	if glog.V(6) {
		glog.Infof("BMP Informational TLV Raw: %s", tools.MessageHex(b))
	}
	tlvs := make([]InformationalTLV, 0)
	for i := 0; i < len(b); {
		// Extracting TLV type 2 bytes
		t := int16(binary.BigEndian.Uint16(b[i : i+2]))
		// Extracting TLV length
		l := int16(binary.BigEndian.Uint16(b[i+2 : i+4]))
		if l > int16(len(b)-(i+4)) {
			return nil, fmt.Errorf("invalid tlv length %d", l)
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
