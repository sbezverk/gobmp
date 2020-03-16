package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// SIDInformationTLV defines SRv6 SID Information TLV
type SIDInformationTLV struct {
	Type   uint16
	Length uint16
	SID    []byte
}

func (srtlv *SIDInformationTLV) String() string {
	var s string
	s += fmt.Sprintf("   SRv6 SID Information TLV Type: %d\n", srtlv.Type)
	s += fmt.Sprintf("      SID: %s\n", internal.MessageHex(srtlv.SID))

	return s
}

// UnmarshalSRv6SIDInformationTLV builds SRv6 SID Information TLV
func UnmarshalSRv6SIDInformationTLV(b []byte) (*SIDInformationTLV, error) {
	glog.V(6).Infof("SRv6 SIDI nformation TLV Raw: %s", internal.MessageHex(b))
	srtlv := SIDInformationTLV{}
	p := 0
	srtlv.Type = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	srtlv.Length = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	srtlv.SID = make([]byte, srtlv.Length)
	copy(srtlv.SID, b[p:p+int(srtlv.Length)])

	return &srtlv, nil
}
