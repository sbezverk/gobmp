package base

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

// String returns a string representation of the label information
func (l *Label) String() string {
	return fmt.Sprintf("Label: %d Exp: %02x BoS: %t", l.Value, l.Exp, l.BoS)
}

// MakeLabel instantiates a new Label object
func MakeLabel(b []byte) (*Label, error) {
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
