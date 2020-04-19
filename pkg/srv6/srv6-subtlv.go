package srv6

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// SubTLV defines SRv6 Sub TLV object
// No RFC yet
type SubTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func (stlv *SubTLV) String() string {
	var s string
	return s
}

// UnmarshalSRv6SubTLV builds a collection of SRv6 Sub TLV
func UnmarshalSRv6SubTLV(b []byte) ([]SubTLV, error) {
	glog.V(6).Infof("SRv6 Sub TLV Raw: %s", tools.MessageHex(b))
	stlvs := make([]SubTLV, 0)
	for p := 0; p < len(b); {
		stlv := SubTLV{}
		stlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		stlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		stlv.Value = make([]byte, stlv.Length)
		copy(stlv.Value, b[p:p+int(stlv.Length)])
		p += int(stlv.Length)
		stlvs = append(stlvs, stlv)
	}

	return stlvs, nil
}
