package bgpls

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// TLV defines BGP-LS TLV object
// https://tootlv.ietf.org/html/rfc7752#section-3.3
type TLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// UnmarshalBGPLSTLV builds Collection of BGP-LS TLVs
func UnmarshalBGPLSTLV(b []byte) ([]TLV, error) {
	if glog.V(6) {
		glog.Infof("BGPLSTLV Raw: %s", tools.MessageHex(b))
	}
	lstlvs := make([]TLV, 0)
	for p := 0; p < len(b); {
		lstlv := TLV{}
		lstlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		lstlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		lstlv.Value = make([]byte, lstlv.Length)
		copy(lstlv.Value, b[p:p+int(lstlv.Length)])
		p += int(lstlv.Length)
		lstlvs = append(lstlvs, lstlv)
	}

	return lstlvs, nil
}
