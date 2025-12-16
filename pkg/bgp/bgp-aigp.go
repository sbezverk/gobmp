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

// UnmarshalAIGP parses AIGP attribute
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

		if tlv.Type == 1 { // AIGP Metric TLV
			if len(b[p:]) < 8 {
				return nil, fmt.Errorf("invalid AIGP metric TLV length")
			}
			tlv.Value = binary.BigEndian.Uint64(b[p : p+8])
			p += 8
		} else {
			// Skip unknown TLVs
			if len(b[p:]) < int(tlv.Length)-3 {
				return nil, fmt.Errorf("invalid TLV length")
			}
			p += int(tlv.Length) - 3
		}

		aigp.TLVs = append(aigp.TLVs, tlv)
	}

	return aigp, nil
}
