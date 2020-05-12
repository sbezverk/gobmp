package base

import (
	"encoding/binary"
)

// TLV defines generic Typle Length Value element
type TLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// UnmarshalTLV builds a map of TLVs elements
func UnmarshalTLV(b []byte) (map[uint16]TLV, error) {
	stlvs := make(map[uint16]TLV)
	for p := 0; p < len(b); {
		stlv := TLV{}
		stlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		stlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		stlv.Value = make([]byte, stlv.Length)
		copy(stlv.Value, b[p:p+int(stlv.Length)])
		stlvs[stlv.Type] = stlv
		p += int(stlv.Length)
	}

	return stlvs, nil
}
