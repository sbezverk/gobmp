package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ExtCommunity defines BGP Extended Commuity
type ExtCommunity struct {
	Type    uint8
	SubType *uint8
	Value   []byte
}

// IsRouteTarget return true is a specific extended community of Route Target type
func (ext *ExtCommunity) IsRouteTarget() bool {
	if ext.SubType != nil {
		if *ext.SubType == 2 {
			return true
		}
	}

	return false
}

func (ext *ExtCommunity) String() string {
	var s string
	switch *ext.SubType {
	case 0x02:
		s += fmt.Sprintf("rt=")
	case 0x03:
		s += fmt.Sprintf("ro=")
	case 0x05:
		s += fmt.Sprintf("odi=")
	case 0x08:
		s += fmt.Sprintf("bdc=")
	case 0x09:
		s += fmt.Sprintf("sas=")
	case 0x0a:
		s += fmt.Sprintf("l2i=")
	}
	switch ext.Type {
	case 0:
		s += fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(ext.Value[0:2]), binary.BigEndian.Uint32(ext.Value[2:]))
	case 1:
		s += fmt.Sprintf("%s:%d", net.IP(ext.Value[0:4]).To4().String(), binary.BigEndian.Uint16(ext.Value[4:]))
	case 2:
		s += fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(ext.Value[0:4]), binary.BigEndian.Uint16(ext.Value[4:]))
	}

	return s
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
