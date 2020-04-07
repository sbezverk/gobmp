package l3vpn

import (
	"encoding/binary"
	"fmt"
)

// Label defines a structure of a single label
type Label struct {
	Value uint32
	Exp   uint8 // 3 bits
	BoS   bool  // 1 bit
}

func makeLabel(b []byte) (*Label, error) {
	l := Label{}
	if len(b) != 3 {
		return nil, fmt.Errorf("invalid length of slice, expected 3 got %d", len(b))
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

// GetRD returns a string representation of RD (one of three types)
func (rd *RD) GetRD() string {
	var s string

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
