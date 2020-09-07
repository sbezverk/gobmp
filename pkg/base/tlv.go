package base

import (
	"encoding/binary"
)

// TLV defines generic Typle Length Value element
type TLV struct {
	Type   uint16 `json:"tlv_type,omitempty"`
	Length uint16 `json:"-"`
	Value  []byte `json:"tlv_value,omitempty"`
}

// SubTLV defines generic Sub Type Length Value element
type SubTLV struct {
	Type   uint16 `json:"sub_tlv_type"`
	Length uint16 `json:"-"`
	Value  []byte `json:"sub_tlv_value,omitempty"`
}

// UnmarshalTLV builds a map of TLVs elements
func UnmarshalTLV(b []byte) (map[uint16]TLV, error) {
	stlvs := make(map[uint16]TLV)
	for p := 0; p < len(b); {
		stlv := TLV{}
		if p+2 > len(b) {
			break
		}
		stlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+2 > len(b) {
			break
		}
		stlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+int(stlv.Length) > len(b) {
			break
		}
		stlv.Value = make([]byte, stlv.Length)
		copy(stlv.Value, b[p:p+int(stlv.Length)])
		stlvs[stlv.Type] = stlv
		p += int(stlv.Length)
	}

	return stlvs, nil
}

// UnmarshalSubTLV builds a slice of Sub TLVs from a slice of bytes
func UnmarshalSubTLV(b []byte) ([]*SubTLV, error) {
	stlvs := make([]*SubTLV, 0)
	for p := 0; p < len(b); {
		stlv := &SubTLV{}
		if p+2 > len(b) {
			break
		}
		stlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+2 > len(b) {
			break
		}
		stlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+int(stlv.Length) > len(b) {
			break
		}
		stlv.Value = make([]byte, stlv.Length)
		copy(stlv.Value, b[p:p+int(stlv.Length)])
		p += int(stlv.Length)
		stlvs = append(stlvs, stlv)
	}

	return stlvs, nil
}
