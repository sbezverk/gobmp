package prefixsid

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/tools"
)

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

// UnmarshalBGPAttrPrefixSID instantiates a prefix sid object
func UnmarshalBGPAttrPrefixSID(b []byte) (*PSid, error) {
	if glog.V(6) {
		glog.Infof("UnmarshalBGPAttrPrefixSID Raw: %+v", tools.MessageHex(b))
	}
	psid := PSid{
		LabelIndex:     nil,
		OriginatorSRGB: nil,
	}
	for p := 0; p < len(b); {
		// Determin the type, currently only type 1 and 3 are supported
		switch b[p] {
		case 1:
			p++
			psid.LabelIndex = &LabelIndexTLV{}
			psid.LabelIndex.Type = 1
			psid.LabelIndex.Length = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			// Skip reserved byte
			p++
			psid.LabelIndex.Flags = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			psid.LabelIndex.LabelIndex = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		case 3:
			p++
			psid.OriginatorSRGB = &OriginatorSRGBTLV{}
			psid.OriginatorSRGB.Type = 1
			psid.OriginatorSRGB.Length = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			psid.OriginatorSRGB.Flags = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			// Multiple SRGB are possible, loop through, each SRGB takes 6 bytes. Subtrack 2 (length of Flags)
			// from the total Value portion length
			psid.OriginatorSRGB.SRGB = make([]SRGB, 0)
			for i := 0; i < int(psid.OriginatorSRGB.Length-2)/6; i++ {
				srgb := SRGB{}
				t := make([]byte, 4)
				copy(t, b[p:p+3])
				srgb.First = binary.BigEndian.Uint32(t)
				p += 3
				t = make([]byte, 4)
				copy(t, b[p:p+3])
				srgb.Number = binary.BigEndian.Uint32(t)
				p += 3
				psid.OriginatorSRGB.SRGB = append(psid.OriginatorSRGB.SRGB, srgb)
			}
		case 5:
			p++
			l := binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			l3, err := srv6.UnmarshalSRv6L3Service(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			psid.SRv6L3Service = l3
			p += int(l)
		default:
			// Skip unknown type, length 2 bytes and the value
			p++
			p += int(binary.BigEndian.Uint16(b[p : p+2]))
			p += 2
		}
	}
	return &psid, nil
}
