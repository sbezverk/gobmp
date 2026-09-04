package mup

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
)

// TLV Types carried by Session Transformed routes per draft Section 3.1.5
const (
	// TLVTypeSessionParameters identifies a 3gpp-5g Session Parameters TLV
	TLVTypeSessionParameters = 1
	// TLVTypeInterworkEndpoint identifies an Interwork Endpoint TLV
	TLVTypeInterworkEndpoint = 2
	// TLVTypeSourceAddress identifies a Source Address TLV
	TLVTypeSourceAddress = 3
)

// sessionParametersLength is the length of the 3gpp-5g Session Parameters TLV
// value: TEID (4 octets) + QFI (1 octet).
const sessionParametersLength = 5

// TLV defines an optional TLV carried by Session Transformed routes.
//
//	+---------------+---------------+------------------------------+
//	| Type (1 octet)| Length(1 oct) | Value (variable)             |
//	+---------------+---------------+------------------------------+
//
// A TLV of an unknown type keeps its raw value so that it stays observable,
// the draft requires unknown types to be ignored rather than rejected.
type TLV struct {
	Type   uint8
	Length uint8
	Value  []byte
}

// SessionParameters returns the TEID and the QFI carried by a 3gpp-5g Session
// Parameters TLV. ok is false for any other TLV type.
func (t *TLV) SessionParameters() (teid uint32, qfi uint8, ok bool) {
	if t.Type != TLVTypeSessionParameters || len(t.Value) != sessionParametersLength {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(t.Value[0:4]), t.Value[4], true
}

// Address returns the IP address carried by an Interwork Endpoint or a Source
// Address TLV. It returns nil for any other TLV type.
func (t *TLV) Address() net.IP {
	if t.Type != TLVTypeInterworkEndpoint && t.Type != TLVTypeSourceAddress {
		return nil
	}
	if len(t.Value) != 4 && len(t.Value) != 16 {
		return nil
	}
	return net.IP(t.Value)
}

// MarshalJSON renders a TLV with its value decoded when the TLV is one of the
// well known types, and as raw octets otherwise.
func (t *TLV) MarshalJSON() ([]byte, error) {
	v := struct {
		Type    uint8   `json:"type"`
		TEID    *uint32 `json:"teid,omitempty"`
		QFI     *uint8  `json:"qfi,omitempty"`
		Address string  `json:"address,omitempty"`
		Value   string  `json:"value,omitempty"`
	}{
		Type: t.Type,
	}
	if teid, qfi, ok := t.SessionParameters(); ok {
		v.TEID = &teid
		v.QFI = &qfi
		return json.Marshal(&v)
	}
	if addr := t.Address(); addr != nil {
		v.Address = addr.String()
		return json.Marshal(&v)
	}
	if len(t.Value) != 0 {
		v.Value = fmt.Sprintf("0x%x", t.Value)
	}
	return json.Marshal(&v)
}

// unmarshalTLVs parses the optional TLVs trailing the mandatory fields of a
// Session Transformed route per draft Sections 3.1.3.1, 3.1.4.1 and 3.1.5.
// A single trailing octet cannot hold a TLV header, and a well known type
// carrying an unexpected length would decode to a bogus value, both make the
// NLRI malformed.
func unmarshalTLVs(b []byte) ([]*TLV, error) {
	if len(b) == 0 {
		return nil, nil
	}
	tlvs := make([]*TLV, 0)
	for p := 0; p < len(b); {
		if p+2 > len(b) {
			return nil, fmt.Errorf("not enough data for TLV header at position %d: need 2 bytes, have %d", p, len(b)-p)
		}
		t := &TLV{
			Type:   b[p],
			Length: b[p+1],
		}
		p += 2
		if p+int(t.Length) > len(b) {
			return nil, fmt.Errorf("not enough data for TLV type %d: need %d bytes, have %d", t.Type, t.Length, len(b)-p)
		}
		if err := checkTLVLength(t.Type, t.Length); err != nil {
			return nil, err
		}
		t.Value = make([]byte, int(t.Length))
		copy(t.Value, b[p:p+int(t.Length)])
		p += int(t.Length)
		tlvs = append(tlvs, t)
	}

	return tlvs, nil
}

// checkTLVLength validates the length of the TLV types the draft defines
func checkTLVLength(typ, length uint8) error {
	switch typ {
	case TLVTypeSessionParameters:
		if length != sessionParametersLength {
			return fmt.Errorf("invalid 3gpp-5g Session Parameters TLV length %d (expected %d)", length, sessionParametersLength)
		}
	case TLVTypeInterworkEndpoint:
		if length != 4 && length != 16 {
			return fmt.Errorf("invalid Interwork Endpoint TLV length %d (expected 4 or 16)", length)
		}
	case TLVTypeSourceAddress:
		if length != 4 && length != 16 {
			return fmt.Errorf("invalid Source Address TLV length %d (expected 4 or 16)", length)
		}
	}

	return nil
}
