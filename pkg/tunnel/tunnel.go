package tunnel

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// TunnelEncapsulation represents the BGP Tunnel Encapsulation Attribute (Type 23)
// RFC 9012: The BGP Tunnel Encapsulation Attribute
type TunnelEncapsulation struct {
	Tunnels []Tunnel `json:"tunnels"`
}

// Tunnel represents a single tunnel TLV within the Tunnel Encapsulation attribute
type Tunnel struct {
	Type    uint16   `json:"type"`              // Tunnel type code
	TypeStr string   `json:"type_name"`         // Human-readable type name
	Length  uint16   `json:"length"`            // Length of Value field
	SubTLVs []SubTLV `json:"sub_tlvs"`
}

// SubTLV represents a sub-TLV within a tunnel TLV
type SubTLV struct {
	Type    uint8           `json:"type"`
	TypeStr string          `json:"type_name"`
	Length  uint16          `json:"length"`
	Value   json.RawMessage `json:"value,omitempty"` // Raw bytes as JSON string
}

// UnmarshalTunnelEncapsulation parses the Tunnel Encapsulation attribute
func UnmarshalTunnelEncapsulation(b []byte) (*TunnelEncapsulation, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty Tunnel Encapsulation attribute")
	}

	te := &TunnelEncapsulation{
		Tunnels: make([]Tunnel, 0),
	}

	p := 0
	for p < len(b) {
		if p+4 > len(b) {
			return nil, fmt.Errorf("insufficient data for tunnel TLV header: need 4 bytes, have %d", len(b)-p)
		}

		tunnel := Tunnel{}
		tunnel.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		tunnel.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		tunnel.TypeStr = GetTunnelTypeName(tunnel.Type)

		if p+int(tunnel.Length) > len(b) {
			return nil, fmt.Errorf("insufficient data for tunnel TLV value: need %d bytes, have %d", tunnel.Length, len(b)-p)
		}

		// Parse sub-TLVs
		subTLVs, err := UnmarshalSubTLVs(b[p : p+int(tunnel.Length)])
		if err != nil {
			return nil, fmt.Errorf("failed to parse sub-TLVs for tunnel type %d: %w", tunnel.Type, err)
		}
		tunnel.SubTLVs = subTLVs

		te.Tunnels = append(te.Tunnels, tunnel)
		p += int(tunnel.Length)
	}

	return te, nil
}

// UnmarshalSubTLVs parses a sequence of sub-TLVs
func UnmarshalSubTLVs(b []byte) ([]SubTLV, error) {
	subTLVs := make([]SubTLV, 0)
	p := 0

	for p < len(b) {
		if p+2 > len(b) {
			return nil, fmt.Errorf("insufficient data for sub-TLV header: need 2 bytes, have %d", len(b)-p)
		}

		subTLV := SubTLV{}
		subTLV.Type = b[p]
		p++

		// Length encoding: 1 octet for types 0-127, 2 octets for types 128-255
		if subTLV.Type < 128 {
			subTLV.Length = uint16(b[p])
			p++
		} else {
			if p+2 > len(b) {
				return nil, fmt.Errorf("insufficient data for 2-octet sub-TLV length: need 2 bytes, have %d", len(b)-p)
			}
			subTLV.Length = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
		}

		subTLV.TypeStr = GetSubTLVTypeName(subTLV.Type)

		if p+int(subTLV.Length) > len(b) {
			return nil, fmt.Errorf("insufficient data for sub-TLV value: need %d bytes, have %d", subTLV.Length, len(b)-p)
		}

		// Store raw value as JSON-encoded hex string
		if subTLV.Length > 0 {
			value := b[p : p+int(subTLV.Length)]
			valueJSON, err := json.Marshal(fmt.Sprintf("%x", value))
			if err != nil {
				return nil, fmt.Errorf("failed to marshal sub-TLV value: %w", err)
			}
			subTLV.Value = valueJSON
		}

		subTLVs = append(subTLVs, subTLV)
		p += int(subTLV.Length)
	}

	return subTLVs, nil
}
