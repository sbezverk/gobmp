package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// InformationalTLV defines Informational TLV per rfc7854
type InformationalTLV struct {
	InformationType   int16 `json:"info_type"`
	InformationLength int16 `json:"info_length"`
	Information       any   `json:"info_value"`
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
		tlv := InformationalTLV{
			InformationType:   t,
			InformationLength: l,
		}
		// According to rfc 9736 types 0, 3 and 4 are string types
		// All other types are binary
		switch t {
		case 0:
			fallthrough
		case 3:
			fallthrough
		case 4:
			tlv.Information = string(b[i+4 : i+4+int(l)])
		default:
			tlv.Information = b[i+4 : i+4+int(l)]
		}
		tlvs = append(tlvs, tlv)
		i += 4 + int(l)
	}

	return tlvs, nil
}
