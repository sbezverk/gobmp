package srv6

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// SIDInformationTLV defines SRv6 SID Information TLV
type SIDInformationTLV struct {
	Type   uint16
	Length uint16
	SID    []byte
}

// UnmarshalSRv6SIDInformationTLV builds SRv6 SID Information TLV slice
func UnmarshalSRv6SIDInformationTLV(b []byte) ([]SIDInformationTLV, error) {
	glog.V(6).Infof("SRv6 SID Information TLV Raw: %s", tools.MessageHex(b))
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
