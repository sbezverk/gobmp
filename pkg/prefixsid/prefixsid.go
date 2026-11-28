package prefixsid

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/tools"
)

// labelIndexLength is the Label-Index TLV Length (RFC 8669 §3.1).
const labelIndexLength = 7

// LabelIndexTLV defines Label index TLV
// https://tools.ietf.org/html/rfc8669#section-3.1
type LabelIndexTLV struct {
	Type       uint8  `json:"-"`
	Length     uint16 `json:"-"`
	Flags      uint16 `json:"flags,omitempty"`
	LabelIndex uint32 `json:"last_index,omitempty"`
}

// SRGB defines a structure of Segment Routing GLobal Block
type SRGB struct {
	First  uint32 `json:"first,omitempty"`
	Number uint32 `json:"number,omitempty"`
}

// OriginatorSRGBTLV defines Originator SRGB TLV and contains the SRGB of the node originating the
// prefix to which the BGP Prefix-SID is attached
// https://tools.ietf.org/html/rfc8669#section-3.2
type OriginatorSRGBTLV struct {
	Type   uint8  `json:"-"`
	Length uint16 `json:"-"`
	Flags  uint16 `json:"flags,omitempty"`
	SRGB   []SRGB `json:"srgb,omitempty"`
}

// PSid defines bgp prefix sid attribute 40
// https://tools.ietf.org/html/rfc8669#section-3
type PSid struct {
	LabelIndex     *LabelIndexTLV     `json:"label_index,omitempty"`
	OriginatorSRGB *OriginatorSRGBTLV `json:"originator_srgb,omitempty"`
	SRv6L3Service  *srv6.L3Service    `json:"srv6_l3_service,omitempty"`
	SRv6L2Service  *srv6.L2Service    `json:"srv6_l2_service,omitempty"`
}

func (p *PSid) IsEmpty() bool {
	return p.LabelIndex == nil && p.OriginatorSRGB == nil && p.SRv6L3Service == nil && p.SRv6L2Service == nil
}

// ErrSRv6ServiceMalformed marks a malformed SRv6 L3 or L2 Service TLV, which
// requires treat-as-withdraw (RFC 9252 §7).
var ErrSRv6ServiceMalformed = errors.New("malformed SRv6 Service TLV")

// UnmarshalBGPAttrPrefixSID instantiates a prefix sid object. A Label-Index or
// Originator SRGB TLV of an invalid length is reported with a result holding the
// other TLVs: only labeled unicast discards the attribute for it (RFC 8669 §6),
// other families ignore the TLV (RFC 8669 §3.1, §3.2). Any other error returns
// no result, and a malformed SRv6 Service TLV is reported as
// ErrSRv6ServiceMalformed in preference to a length error. The content of the
// SRv6 L2 Service TLV is validated but not returned.
func UnmarshalBGPAttrPrefixSID(b []byte) (*PSid, error) {
	if glog.V(6) {
		glog.Infof("UnmarshalBGPAttrPrefixSID Raw: %+v", tools.MessageHex(b))
	}
	psid := PSid{
		LabelIndex:     nil,
		OriginatorSRGB: nil,
	}
	// lengthErr collects errors which leave the TLV framing intact, so the walk
	// goes on to the remaining TLVs.
	var lengthErr error
	l2Seen := false
	for p := 0; p < len(b); {
		if p+3 > len(b) {
			err := fmt.Errorf("prefix SID truncated at offset %d: need at least 3 bytes for TLV header, have %d", p, len(b)-p)
			if b[p] == 5 || b[p] == 6 {
				return nil, fmt.Errorf("%w: %w", ErrSRv6ServiceMalformed, err)
			}
			return nil, err
		}
		switch b[p] {
		case 1:
			p++
			length := binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			if p+int(length) > len(b) {
				return nil, fmt.Errorf("prefix SID label index TLV truncated at offset %d: need %d bytes, have %d", p, length, len(b)-p)
			}
			// RFC 8669 §3.1 fixes the length.
			if length != labelIndexLength {
				lengthErr = errors.Join(lengthErr,
					fmt.Errorf("prefix SID label index TLV length %d, want %d", length, labelIndexLength))
				p += int(length)
				continue
			}
			psid.LabelIndex = &LabelIndexTLV{}
			psid.LabelIndex.Type = 1
			psid.LabelIndex.Length = length
			// Skip reserved byte
			p++
			psid.LabelIndex.Flags = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			psid.LabelIndex.LabelIndex = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		case 3:
			p++
			length := binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			if p+int(length) > len(b) {
				return nil, fmt.Errorf("prefix SID originator SRGB value truncated at offset %d: need %d bytes, have %d", p, length, len(b)-p)
			}
			if length < 2 {
				lengthErr = errors.Join(lengthErr,
					fmt.Errorf("prefix SID originator SRGB length too short: need at least 2 bytes for Flags, have %d", length))
				p += int(length)
				continue
			}
			psid.OriginatorSRGB = &OriginatorSRGBTLV{}
			psid.OriginatorSRGB.Type = 3
			psid.OriginatorSRGB.Length = length
			psid.OriginatorSRGB.Flags = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			psid.OriginatorSRGB.SRGB = make([]SRGB, 0)
			srgbBytes := int(psid.OriginatorSRGB.Length - 2)
			srgbCount := srgbBytes / 6
			for i := 0; i < srgbCount; i++ {
				srgb := SRGB{}
				t := make([]byte, 4)
				copy(t[1:], b[p:p+3])
				srgb.First = binary.BigEndian.Uint32(t)
				p += 3
				t = make([]byte, 4)
				copy(t[1:], b[p:p+3])
				srgb.Number = binary.BigEndian.Uint32(t)
				p += 3
				psid.OriginatorSRGB.SRGB = append(psid.OriginatorSRGB.SRGB, srgb)
			}
			// Skip any trailing bytes not forming a complete SRGB entry
			p += srgbBytes - srgbCount*6
		case 5, 6:
			isL2, name := b[p] == 6, "L3"
			if isL2 {
				name = "L2"
			}
			p++
			l := binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			if p+int(l) > len(b) {
				return nil, fmt.Errorf("%w: prefix SID SRv6 %s service value truncated at offset %d: need %d bytes, have %d",
					ErrSRv6ServiceMalformed, name, p, l, len(b)-p)
			}
			// RFC 9252 §7: all but the first SRv6 Service TLV of a type MUST be ignored.
			if (isL2 && l2Seen) || (!isL2 && psid.SRv6L3Service != nil) {
				p += int(l)
				continue
			}
			if l == 0 {
				return nil, fmt.Errorf("%w: prefix SID SRv6 %s service TLV at offset %d has zero length",
					ErrSRv6ServiceMalformed, name, p-3)
			}
			// RFC 9252 §2: both Service TLVs have the same Sub-TLV structure.
			service, err := srv6.UnmarshalSRv6L3Service(b[p : p+int(l)])
			if err != nil {
				return nil, fmt.Errorf("%w: prefix SID SRv6 %s service TLV at offset %d: %w",
					ErrSRv6ServiceMalformed, name, p-3, err)
			}
			if isL2 {
				l2Seen = true
			} else {
				psid.SRv6L3Service = service
			}
			p += int(l)
		default:
			p++
			if p+2 > len(b) {
				return nil, fmt.Errorf("prefix SID unknown TLV truncated at offset %d: need 2 bytes for length, have %d", p, len(b)-p)
			}
			l := int(binary.BigEndian.Uint16(b[p : p+2]))
			p += 2
			if p+l > len(b) {
				return nil, fmt.Errorf("prefix SID unknown TLV value truncated at offset %d: need %d bytes, have %d", p, l, len(b)-p)
			}
			p += l
		}
	}
	return &psid, lengthErr
}

// Equal compares two PSid objects for equality (RFC 8669)
// Returns true if equal, false otherwise, along with a list of differences
func (p *PSid) Equal(o *PSid) (bool, []string) {
	if p == nil && o == nil {
		return true, nil
	}
	if p == nil || o == nil {
		return false, []string{"one prefix sid is nil"}
	}

	equal := true
	diffs := make([]string, 0)

	// Compare LabelIndex
	if (p.LabelIndex == nil) != (o.LabelIndex == nil) {
		equal = false
		diffs = append(diffs, "label index nil mismatch")
	} else if p.LabelIndex != nil {
		if p.LabelIndex.Flags != o.LabelIndex.Flags {
			equal = false
			diffs = append(diffs, "label index flags mismatch")
		}
		if p.LabelIndex.LabelIndex != o.LabelIndex.LabelIndex {
			equal = false
			diffs = append(diffs, "label index value mismatch")
		}
	}

	// Compare OriginatorSRGB
	if (p.OriginatorSRGB == nil) != (o.OriginatorSRGB == nil) {
		equal = false
		diffs = append(diffs, "originator srgb nil mismatch")
	} else if p.OriginatorSRGB != nil {
		if p.OriginatorSRGB.Flags != o.OriginatorSRGB.Flags {
			equal = false
			diffs = append(diffs, "originator srgb flags mismatch")
		}
		if len(p.OriginatorSRGB.SRGB) != len(o.OriginatorSRGB.SRGB) {
			equal = false
			diffs = append(diffs, "originator srgb length mismatch")
		} else {
			for i := range p.OriginatorSRGB.SRGB {
				if p.OriginatorSRGB.SRGB[i].First != o.OriginatorSRGB.SRGB[i].First {
					equal = false
					diffs = append(diffs, "originator srgb first mismatch")
				}
				if p.OriginatorSRGB.SRGB[i].Number != o.OriginatorSRGB.SRGB[i].Number {
					equal = false
					diffs = append(diffs, "originator srgb number mismatch")
				}
			}
		}
	}

	// Compare SRv6L3Service
	if (p.SRv6L3Service == nil) != (o.SRv6L3Service == nil) {
		equal = false
		diffs = append(diffs, "srv6 l3 service nil mismatch")
	}

	// Compare SRv6L2Service
	if (p.SRv6L2Service == nil) != (o.SRv6L2Service == nil) {
		equal = false
		diffs = append(diffs, "srv6 l2 service nil mismatch")
	}

	return equal, diffs
}
