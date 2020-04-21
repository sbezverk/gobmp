package bgp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/tools"
)

// ExtCommunity defines BGP Extended Commuity
type ExtCommunity struct {
	Type    uint8
	SubType *uint8
	Value   []byte
}

// IsRouteTarget return true is a specific extended community of Route Target type
func (ext *ExtCommunity) IsRouteTarget() bool {
	var subType uint8
	if ext.SubType == nil {
		subType = 0xff
	} else {
		subType = *ext.SubType
	}
	if ext.SubType != nil {
		if subType == 2 {
			return true
		}
	}

	return false
}

func (ext *ExtCommunity) String() string {
	var s string
	var prefix string
	var subType uint8
	if ext.SubType == nil {
		subType = 0xff
	} else {
		subType = *ext.SubType
	}
	switch subType {
	case 0x0:
		prefix = "mmb="
	case 0x01:
		prefix = "lb="
	case 0x02:
		prefix = "rt="
	case 0x03:
		prefix = "ro="
	case 0x05:
		prefix = "odi="
	case 0x06:
		prefix = "df="
	case 0x08:
		prefix = "bdc="
	case 0x09:
		prefix = "sas="
	case 0x0a:
		prefix = "l2i="
	}
	switch ext.Type {
	case 0:
		s += fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(ext.Value[0:2]), binary.BigEndian.Uint32(ext.Value[2:]))
	case 1:
		s += fmt.Sprintf("%s:%d", net.IP(ext.Value[0:4]).To4().String(), binary.BigEndian.Uint16(ext.Value[4:]))
	case 2:
		s += fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(ext.Value[0:4]), binary.BigEndian.Uint16(ext.Value[4:]))
	case 3:
		switch subType {
		case 0xb:
			prefix = "color="
			s += fmt.Sprintf("%d", binary.BigEndian.Uint32(ext.Value[0:4]))
		case 0xc:
			prefix = "tunnel-type="
			s += fmt.Sprintf("%d", binary.BigEndian.Uint16(ext.Value[2:4]))
		default:
			prefix = fmt.Sprintf("%d=", subType)
			s += fmt.Sprintf("%d", binary.BigEndian.Uint32(ext.Value[0:4]))
		}
	case 6:
		// EVPN related extended communities
		switch subType {
		case 0x01:
			// ESI Label Extended Community
			l := make([]byte, 4)
			copy(l, ext.Value[3:])
			s += fmt.Sprintf("%d:%d", ext.Value[0], binary.BigEndian.Uint32(l))
		case 0x02:
			// ES-Import Route Target
			for i, m := range ext.Value {
				s += fmt.Sprintf("%02x", m)
				if i < len(ext.Value)-1 {
					s += ":"
				}
			}
		case 0x00:
			// MAC Mobility Extended Community
			s += fmt.Sprintf("%d:%d", ext.Value[0], binary.BigEndian.Uint32(ext.Value[2:]))
		case 0x06:
			// The DF Election Extended Community
			s += fmt.Sprintf("%d:0x%04x", ext.Value[0], binary.BigEndian.Uint16(ext.Value[1:]))
		default:
			prefix = fmt.Sprintf("%d=", subType)
			s += fmt.Sprintf("%d", binary.BigEndian.Uint32(ext.Value[0:4]))
		}
	default:
		prefix = "unknown="
		s += fmt.Sprintf("Type: %d Subtype: %d Value: %s", ext.Type, subType, tools.MessageHex(ext.Value))
	}

	return prefix + s
}

func makeExtCommunity(b []byte) (*ExtCommunity, error) {
	ext := ExtCommunity{}
	if len(b) != 8 {
		return nil, fmt.Errorf("invalid length expected 8 got %d", len(b))
	}
	p := 0
	ext.Type = b[p]
	p++
	l := 7
	switch ext.Type & 0x3f {
	case 0:
		fallthrough
	case 1:
		fallthrough
	case 2:
		fallthrough
	case 6:
		st := uint8(b[p])
		ext.SubType = &st
		l = 6
		p++
	case 3:
		st := uint8(b[p])
		ext.SubType = &st
		l = 6
		p += 3
	}
	ext.Value = make([]byte, l)
	copy(ext.Value, b[p:])

	return &ext, nil
}

// UnmarshalBGPExtCommunity builds a slice of Extended Communities
func UnmarshalBGPExtCommunity(b []byte) ([]ExtCommunity, error) {
	exts := make([]ExtCommunity, 0)
	for p := 0; p < len(b); {
		ext, err := makeExtCommunity(b[p : p+8])
		if err != nil {
			return nil, err
		}
		p += 8
		exts = append(exts, *ext)
	}

	return exts, nil
}
