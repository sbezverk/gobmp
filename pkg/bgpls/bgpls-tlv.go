package bgpls

import (
	"encoding/binary"
	"fmt"

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

// ValidateBGPLSTLV walks a BGP-LS Attribute (path attribute 29) TLV stream and
// reports whether every TLV's Type/Length header fits within the buffer. Unlike
// UnmarshalBGPLSTLV it does not allocate per-TLV value slices, so it is safe to
// call from the BGP path-attribute parser hot path. Detailed per-TLV decoding
// happens later via UnmarshalBGPLSTLV when a Link-State NLRI is emitted.
func ValidateBGPLSTLV(b []byte) error {
	for p := 0; p < len(b); {
		if p+4 > len(b) {
			return fmt.Errorf("not enough bytes to unmarshal BGP-LS TLV header: need 4 bytes, have %d", len(b)-p)
		}
		l := binary.BigEndian.Uint16(b[p+2 : p+4])
		p += 4
		if p+int(l) > len(b) {
			return fmt.Errorf("not enough bytes to unmarshal BGP-LS TLV Value: need %d bytes, have %d", l, len(b)-p)
		}
		p += int(l)
	}
	return nil
}

// UnmarshalBGPLSTLV builds Collection of BGP-LS TLVs
func UnmarshalBGPLSTLV(b []byte) ([]TLV, error) {
	if glog.V(6) {
		glog.Infof("BGPLSTLV Raw: %s", tools.MessageHex(b))
	}
	lstlvs := make([]TLV, 0)
	if len(b) == 0 {
		return lstlvs, nil
	}
	for p := 0; p < len(b); {
		lstlv := TLV{}
		if p+2 > len(b) {
			return nil, fmt.Errorf("not enough bytes to unmarshal BGP-LS TLV Type: need 2 bytes, have %d", len(b)-p)
		}
		lstlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+2 > len(b) {
			return nil, fmt.Errorf("not enough bytes to unmarshal BGP-LS TLV Length: need 2 bytes, have %d", len(b)-p)
		}
		lstlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+int(lstlv.Length) > len(b) {
			return nil, fmt.Errorf("not enough bytes to unmarshal BGP-LS TLV Value: need %d bytes, have %d", lstlv.Length, len(b)-p)
		}
		lstlv.Value = make([]byte, lstlv.Length)
		copy(lstlv.Value, b[p:p+int(lstlv.Length)])
		p += int(lstlv.Length)
		lstlvs = append(lstlvs, lstlv)
	}

	return lstlvs, nil
}
