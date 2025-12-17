package bgp

import (
	"encoding/binary"
	"fmt"
)

// BGPPrefixSID defines BGP Prefix-SID attribute structure per RFC 8669
type BGPPrefixSID struct {
	TLVs []BGPPrefixSIDTLV `json:"tlvs,omitempty"`
}

// BGPPrefixSIDTLV defines Prefix-SID TLV structure
type BGPPrefixSIDTLV struct {
	Type   uint8  `json:"type"`
	Length uint16 `json:"length"`
	// Type-specific fields
	LabelIndex     *LabelIndexTLV     `json:"label_index,omitempty"`     // Type 1
	OriginatorSRGB *OriginatorSRGBTLV `json:"originator_srgb,omitempty"` // Type 3
	UnknownValue   []byte             `json:"unknown_value,omitempty"`   // For unknown types
}

// LabelIndexTLV defines Label-Index TLV structure (Type 1) per RFC 8669 Section 3.1
type LabelIndexTLV struct {
	Flags      uint16 `json:"flags"`
	LabelIndex uint32 `json:"label_index"`
}

// OriginatorSRGBTLV defines Originator SRGB TLV structure (Type 3) per RFC 8669 Section 3.2
type OriginatorSRGBTLV struct {
	Flags  uint16      `json:"flags"`
	Ranges []SRGBRange `json:"ranges,omitempty"`
}

// SRGBRange defines a single SRGB range
type SRGBRange struct {
	Base  uint32 `json:"base"`  // 24-bit value (3 octets)
	Range uint32 `json:"range"` // 24-bit value (3 octets)
}

// UnmarshalBGPPrefixSID parses BGP Prefix-SID attribute
func UnmarshalBGPPrefixSID(b []byte) (*BGPPrefixSID, error) {
	if len(b) < 3 {
		return nil, fmt.Errorf("invalid BGP Prefix-SID length: %d", len(b))
	}

	sid := &BGPPrefixSID{
		TLVs: make([]BGPPrefixSIDTLV, 0),
	}

	p := 0
	for p < len(b) {
		if len(b[p:]) < 3 {
			break
		}

		tlv := BGPPrefixSIDTLV{
			Type:   b[p],
			Length: binary.BigEndian.Uint16(b[p+1 : p+3]),
		}
		p += 3

		if len(b[p:]) < int(tlv.Length) {
			return nil, fmt.Errorf("invalid TLV length: expected %d, remaining %d", tlv.Length, len(b[p:]))
		}

		value := b[p : p+int(tlv.Length)]

		switch tlv.Type {
		case 1:
			// Label-Index TLV (RFC 8669 Section 3.1)
			labelIndex, err := unmarshalLabelIndexTLV(value)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal Label-Index TLV: %v", err)
			}
			tlv.LabelIndex = labelIndex

		case 3:
			// Originator SRGB TLV (RFC 8669 Section 3.2)
			srgb, err := unmarshalOriginatorSRGBTLV(value)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal Originator SRGB TLV: %v", err)
			}
			tlv.OriginatorSRGB = srgb

		default:
			// Unknown TLV types are preserved per RFC 8669
			tlv.UnknownValue = make([]byte, len(value))
			copy(tlv.UnknownValue, value)
		}

		sid.TLVs = append(sid.TLVs, tlv)
		p += int(tlv.Length)
	}

	return sid, nil
}

// unmarshalLabelIndexTLV parses Label-Index TLV (Type 1)
// Format: Reserved (1 byte) + Flags (2 bytes) + Label Index (4 bytes)
func unmarshalLabelIndexTLV(b []byte) (*LabelIndexTLV, error) {
	if len(b) < 7 {
		return nil, fmt.Errorf("invalid Label-Index TLV length: expected 7, got %d", len(b))
	}

	return &LabelIndexTLV{
		Flags:      binary.BigEndian.Uint16(b[1:3]), // Skip reserved byte
		LabelIndex: binary.BigEndian.Uint32(b[3:7]),
	}, nil
}

// unmarshalOriginatorSRGBTLV parses Originator SRGB TLV (Type 3)
// Format: Flags (2 bytes) + SRGB Ranges (6 bytes per range)
func unmarshalOriginatorSRGBTLV(b []byte) (*OriginatorSRGBTLV, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("invalid Originator SRGB TLV length: minimum 2, got %d", len(b))
	}

	srgb := &OriginatorSRGBTLV{
		Flags:  binary.BigEndian.Uint16(b[0:2]),
		Ranges: make([]SRGBRange, 0),
	}

	// Parse SRGB ranges (6 bytes each)
	p := 2
	for p < len(b) {
		if len(b[p:]) < 6 {
			return nil, fmt.Errorf("invalid SRGB range: expected 6 bytes, got %d", len(b[p:]))
		}

		// Parse 24-bit base value (3 octets)
		base := uint32(b[p])<<16 | uint32(b[p+1])<<8 | uint32(b[p+2])

		// Parse 24-bit range value (3 octets)
		rangeVal := uint32(b[p+3])<<16 | uint32(b[p+4])<<8 | uint32(b[p+5])

		srgb.Ranges = append(srgb.Ranges, SRGBRange{
			Base:  base,
			Range: rangeVal,
		})

		p += 6
	}

	return srgb, nil
}
