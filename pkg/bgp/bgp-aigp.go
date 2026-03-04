package bgp

import (
	"encoding/binary"
	"fmt"
)

// AIGP defines AIGP attribute structure per RFC 7311
type AIGP struct {
	TLVs []AIGPTLV `json:"tlvs,omitempty"`
}

// AIGPTLV defines AIGP TLV structure
type AIGPTLV struct {
	Type   uint8  `json:"type"`
	Length uint16 `json:"length"`
	Value  uint64 `json:"value,omitempty"` // For Type 1 (AIGP Metric)
}

// UnmarshalAIGP parses AIGP attribute (RFC 7311).
//
// The only currently defined TLV type is Type 1 (AIGP Metric TLV):
//
//	Type   = 1         (1 octet)
//	Length = 11        (2 octets; includes the Type and Length fields themselves)
//	Value  = uint64    (8 octets; accumulated IGP metric)
//
// The IANA "BGP AIGP Attribute Types" registry (Type 0 reserved, Types 2-255 unassigned)
// defines no other types as of RFC 7311. Unknown types are skipped per RFC 7311 §3.2.
func UnmarshalAIGP(b []byte) (*AIGP, error) {
	if len(b) < 3 {
		return nil, fmt.Errorf("invalid AIGP length: %d", len(b))
	}

	aigp := &AIGP{
		TLVs: make([]AIGPTLV, 0),
	}

	p := 0
	for p < len(b) {
		if len(b[p:]) < 3 {
			break
		}

		tlv := AIGPTLV{
			Type:   b[p],
			Length: binary.BigEndian.Uint16(b[p+1 : p+3]),
		}
		p += 3

		// RFC 7311 §3: Length includes the Type and Length octets (3 bytes),
		// so the value region is (Length - 3) bytes. Guard against truncation.
		valueLen := int(tlv.Length) - 3
		if valueLen < 0 || p+valueLen > len(b) {
			return nil, fmt.Errorf("invalid AIGP TLV length %d at offset %d", tlv.Length, p-3)
		}

		if tlv.Type == 1 {
			// AIGP Metric TLV: Length MUST be 11 (3 header + 8 value bytes).
			if tlv.Length != 11 {
				return nil, fmt.Errorf("malformed AIGP Metric TLV: expected length 11, got %d", tlv.Length)
			}
			tlv.Value = binary.BigEndian.Uint64(b[p : p+8])
		}
		// Unknown TLV types are skipped per RFC 7311 §3.2 (attribute MUST NOT be
		// considered malformed merely because it contains TLVs of unknown types).
		p += valueLen

		aigp.TLVs = append(aigp.TLVs, tlv)
	}

	return aigp, nil
}
