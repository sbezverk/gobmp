package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// SIDInformationTLV defines SRv6 SID Information TLV
type SIDInformationTLV struct {
	Type   uint16
	Length uint16
	SID    []byte
}

func (tlv *SIDInformationTLV) String() string {
	var s string
	s += fmt.Sprintf("   SRv6 SID Information TLV Type: %d\n", tlv.Type)
	s += fmt.Sprintf("      SID: %s\n", tools.MessageHex(tlv.SID))

	return s
}

// MarshalJSON defines a method to Marshal Link Descriptor object into JSON format
func (tlv *SIDInformationTLV) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"Type\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", tlv.Type))...)
	jsonData = append(jsonData, []byte("\"Length\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", tlv.Length))...)
	jsonData = append(jsonData, []byte("\"SID\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%s", tools.RawBytesToJSON(tlv.SID)))...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalSRv6SIDInformationTLV builds SRv6 SID Information TLV slice
func UnmarshalSRv6SIDInformationTLV(b []byte) ([]SIDInformationTLV, error) {
	glog.V(5).Infof("SRv6 SID Information TLV Raw: %s", tools.MessageHex(b))
	tlvs := make([]SIDInformationTLV, 0)
	for p := 0; p < len(b); {
		tlv := SIDInformationTLV{}
		tlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		tlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		tlv.SID = make([]byte, tlv.Length)
		copy(tlv.SID, b[p:p+int(tlv.Length)])
		tlvs = append(tlvs, tlv)
		p += int(tlv.Length)
	}
	return tlvs, nil
}
