package bgp

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"sort"
)

const maxSerializedBGPMessage = 4096

// Serialize returns a complete BGP OPEN, including its marker. Length, Type,
// OptParamLen and parameter lengths are derived without modifying o. Capabilities
// are emitted in code order; their original grouping is not retained by parsing.
// RFC 9072 encoding is selected when ordinary optional parameters do not fit.
func (o *OpenMessage) Serialize() ([]byte, error) {
	if o == nil {
		return nil, fmt.Errorf("nil BGP OPEN")
	}
	if o.Version != 4 || (o.HoldTime != 0 && o.HoldTime < 3) || len(o.BGPID) != 4 || binary.BigEndian.Uint32(o.BGPID) == 0 {
		return nil, fmt.Errorf("invalid BGP OPEN version, hold time or BGP identifier")
	}
	params := append([]InformationalTLV(nil), o.OptionalParameters...)
	for _, p := range params {
		if p.Type == 255 {
			return nil, fmt.Errorf("OPEN optional parameter type 255 is reserved for the RFC 9072 sentinel")
		}
		if p.Type == 2 {
			if len(o.Capabilities) != 0 {
				return nil, fmt.Errorf("capabilities supplied in both optional parameters and capability map")
			}
			if err := validateCapabilities(p.Value); err != nil {
				return nil, err
			}
		}
	}
	codes := make([]int, 0, len(o.Capabilities))
	for code := range o.Capabilities {
		codes = append(codes, int(code))
	}
	sort.Ints(codes)
	for _, code := range codes {
		for _, data := range o.Capabilities[uint8(code)] {
			if data == nil || len(data.Value) > 255 {
				return nil, fmt.Errorf("invalid capability %d value", code)
			}
			value := append([]byte{byte(code), byte(len(data.Value))}, data.Value...)
			if err := validateCapabilities(value); err != nil {
				return nil, err
			}
			params = append(params, InformationalTLV{Type: 2, Value: value})
		}
	}
	ordinaryLen := 0
	extended := false
	for _, p := range params {
		if len(p.Value) > 65535 {
			return nil, fmt.Errorf("OPEN parameter %d exceeds uint16 length", p.Type)
		}
		ordinaryLen += 2 + len(p.Value)
		extended = extended || len(p.Value) > 255
	}
	extended = extended || ordinaryLen > 255
	opt := make([]byte, 0)
	for _, p := range params {
		opt = append(opt, p.Type)
		if extended {
			opt = binary.BigEndian.AppendUint16(opt, uint16(len(p.Value)))
		} else {
			opt = append(opt, byte(len(p.Value)))
		}
		opt = append(opt, p.Value...)
		if len(opt) > maxSerializedBGPMessage {
			return nil, fmt.Errorf("BGP OPEN exceeds 4096 bytes")
		}
	}
	body := []byte{4}
	body = binary.BigEndian.AppendUint16(body, o.MyAS)
	body = binary.BigEndian.AppendUint16(body, o.HoldTime)
	body = append(body, o.BGPID...)
	if extended {
		body = append(body, 255, 255)
		body = binary.BigEndian.AppendUint16(body, uint16(len(opt)))
	} else {
		body = append(body, byte(len(opt)))
	}
	body = append(body, opt...)
	return serializeFrame(1, body)
}

// Serialize returns a complete BGP UPDATE using WithdrawnRoutes, PathAttributes
// and NLRI as its wire representation. All length fields are derived. Raw
// attributes are authoritative over the derived BaseAttributes cache; semantic
// BaseAttributes alone cannot be encoded. ASN widths and ADD-PATH/NLRI bytes
// must already match the monitored session. RFC 8671 section 5.2 zero-length
// ORIGIN, NEXT_HOP and LOCAL_PREF placeholders are preserved here; the complete
// BMP Message validates whether its RIB view permits them. Extended BGP
// messages are unsupported.
func (u *Update) Serialize() ([]byte, error) {
	if u == nil {
		return nil, fmt.Errorf("nil BGP UPDATE")
	}
	if len(u.PathAttributes) == 0 && semanticAttributesPresent(u.BaseAttributes) {
		return nil, fmt.Errorf("cannot serialize BaseAttributes without raw PathAttributes")
	}
	if len(u.WithdrawnRoutes) > maxSerializedBGPMessage || len(u.NLRI) > maxSerializedBGPMessage {
		return nil, fmt.Errorf("BGP UPDATE exceeds 4096 bytes")
	}
	attrs := make([]byte, 0)
	for _, attr := range u.PathAttributes {
		if err := validateWireAttribute(attr); err != nil {
			return nil, err
		}
		if len(attr.Attribute) > 65535 || attr.AttributeType == 0 || attr.AttributeTypeFlags&0x0f != 0 {
			return nil, fmt.Errorf("invalid path attribute %d", attr.AttributeType)
		}
		flags := attr.AttributeTypeFlags
		if len(attr.Attribute) > 255 {
			flags |= 0x10
		}
		attrs = append(attrs, flags, attr.AttributeType)
		if flags&0x10 != 0 {
			attrs = binary.BigEndian.AppendUint16(attrs, uint16(len(attr.Attribute)))
		} else {
			attrs = append(attrs, byte(len(attr.Attribute)))
		}
		attrs = append(attrs, attr.Attribute...)
		if len(attrs) > maxSerializedBGPMessage {
			return nil, fmt.Errorf("BGP UPDATE exceeds 4096 bytes")
		}
	}
	body := binary.BigEndian.AppendUint16(nil, uint16(len(u.WithdrawnRoutes)))
	body = append(body, u.WithdrawnRoutes...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(body, attrs...)
	body = append(body, u.NLRI...)
	// Reuse the existing attribute validation without rebuilding semantic fields.
	if _, err := UnmarshalBGPUpdate(body); err != nil {
		return nil, fmt.Errorf("invalid BGP UPDATE: %w", err)
	}
	return serializeFrame(2, body)
}

func semanticAttributesPresent(b *BaseAttributes) bool {
	if b == nil {
		return false
	}
	v := reflect.ValueOf(*b)
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		// The parser populates the hash even for an empty UPDATE. Neither this
		// hash nor its private memoization cache represents a wire attribute.
		if t.Field(i).Name == "BaseAttrHash" || t.Field(i).PkgPath != "" {
			continue
		}
		f := v.Field(i)
		if (f.Kind() == reflect.Slice || f.Kind() == reflect.Map) && f.Len() == 0 {
			continue
		}
		if !f.IsZero() {
			return true
		}
	}
	return false
}

func serializeFrame(kind byte, body []byte) ([]byte, error) {
	if 19+len(body) > maxSerializedBGPMessage {
		return nil, fmt.Errorf("BGP message exceeds 4096 bytes")
	}
	b := make([]byte, 19, 19+len(body))
	for i := 0; i < 16; i++ {
		b[i] = 255
	}
	binary.BigEndian.PutUint16(b[16:18], uint16(19+len(body)))
	b[18] = kind
	return append(b, body...), nil
}

// Validate fixed-format values that the permissive collector reader may accept
// defensively. Opaque NLRI and unrecognised attribute types remain wire inputs.
func validateWireAttribute(a PathAttribute) error {
	n := len(a.Attribute)
	valid := true
	switch a.AttributeType {
	case 1:
		valid = n == 0 || (n == 1 && a.Attribute[0] <= 2)
	case 3, 5:
		valid = n == 0 || n == 4
	case 4, 9, 35:
		valid = n == 4
	case 6:
		valid = n == 0
	case 7:
		valid = n == 6 || n == 8
	case 8, 10:
		valid = n%4 == 0
	case 16:
		valid = n%8 == 0
	case 18:
		valid = n == 8
	case 25:
		valid = n%20 == 0
	case 32:
		valid = n%12 == 0
	}
	if !valid {
		return fmt.Errorf("invalid value length or encoding for path attribute %d", a.AttributeType)
	}
	return nil
}

func validateCapabilities(value []byte) error {
	caps, err := UnmarshalBGPCapability(value)
	if err != nil {
		return err
	}
	for _, c := range caps[65] {
		if len(c.Value) != 4 {
			return fmt.Errorf("AS4 capability requires four bytes")
		}
	}
	return nil
}
