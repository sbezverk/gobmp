package l3vpn

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Label defines a structure of a single label
type Label struct {
	Value uint32
	Exp   uint8 // 3 bits
	BoS   bool  // 1 bit
}

// String returns a string representation of the label information
func (l *Label) String() string {
	return fmt.Sprintf("Label: %d Exp: %02x BoS: %t", l.Value, l.Exp, l.BoS)
}

func makeLabel(b []byte) (*Label, error) {
	l := Label{}
	if len(b) != 3 {
		return nil, fmt.Errorf("invalid length expected 3 got %d", len(b))
	}
	v := make([]byte, 4)
	copy(v[1:], b)
	l.Value = binary.BigEndian.Uint32(v)
	l.Value = l.Value >> 4
	// Move Exp bits to the beggining of the byte and leave only 3 bits, mask the rest.
	l.Exp = uint8(b[2]&0x07) >> 1
	l.BoS = b[2]&0x01 == 1

	return &l, nil
}

// RD defines a structure of VPN prefixe's Route Distinguisher
type RD struct {
	Type  uint16
	Value []byte
}

func makeRD(b []byte) (*RD, error) {
	rd := RD{}
	if len(b) != 8 {
		return nil, fmt.Errorf("invalid length expected 8 got %d", len(b))
	}
	rd.Type = binary.BigEndian.Uint16(b[0:2])
	if rd.Type > 2 {
		return nil, fmt.Errorf("invalid rd type %d", rd.Type)
	}
	rd.Value = make([]byte, 6)
	copy(rd.Value, b[2:])

	return &rd, nil
}

// GetRD returns a string representation of RD (one of three types)
func (rd *RD) String() string {
	var s string
	switch rd.Type {
	case 0:
		s += fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(rd.Value[0:2]), binary.BigEndian.Uint32(rd.Value[2:]))
	case 1:
		s += fmt.Sprintf("%s:%d", net.IP(rd.Value[0:4]).To4().String(), binary.BigEndian.Uint16(rd.Value[4:]))
	case 2:
		s += fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(rd.Value[0:4]), binary.BigEndian.Uint16(rd.Value[4:]))
	}

	return s
}

// NLRI defines L3 VPN NLRI object
type NLRI struct {
	Length uint8
	Labels []*Label
	RD     RD
	Prefix []byte
}

// UnmarshalL3VPNNLRI instantiates a L3 VPN NLRI object
func UnmarshalL3VPNNLRI(b []byte) (*NLRI, error) {
	n := NLRI{}
	p := 0
	// Getting length of NLRI in bytes
	n.Length = uint8(b[p] / 8)
	p++
	n.Labels = make([]*Label, 0)
	// subtract 12 for the length as label stack follows by RD 8 bytes and prefix 4 bytes
	for p < len(b)-12 {
		l, err := makeLabel(b[p : p+3])
		if err != nil {
			return nil, err
		}
		n.Labels = append(n.Labels, l)
		p += 3
	}

	return &n, nil
}
