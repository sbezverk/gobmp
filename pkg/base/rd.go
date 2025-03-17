package base

import (
	"encoding/binary"
	"fmt"
	"net"
)

type RD struct {
	Type  uint16
	Value []byte
}

// MakeRD instantiates a new RD object from an 8-byte slice
// If the slice is not 8 bytes or the RD type is out-of-range (>2),
// this function silently forces RD type 1 with a zeroed 6-byte value
// so that no error or panic occurs
func MakeRD(b []byte) (*RD, error) {
	if len(b) != 8 {
		// Force type=1 with a zeroed Value
		return &RD{
			Type:  1,
			Value: []byte{0, 0, 0, 0, 0, 0},
		}, nil
	}

	rdType := binary.BigEndian.Uint16(b[0:2])
	if rdType > 2 {
		// Force type=1 if out-of-range
		rdType = 1
	}
	rd := RD{
		Type:  rdType,
		Value: make([]byte, 6),
	}
	copy(rd.Value, b[2:])
	return &rd, nil
}

// String returns a string representation of the RD
// For type=1, the first 4 bytes are displayed as an IPv4 address, and
// the last 2 bytes as a numeric value
func (rd *RD) String() string {
	switch rd.Type {
	case 0:
		// Type=0: 2 bytes + 4 bytes
		return fmt.Sprintf("%d:%d",
			binary.BigEndian.Uint16(rd.Value[0:2]),
			binary.BigEndian.Uint32(rd.Value[2:]),
		)
	case 1:
		// Type=1: IPv4 + 2 bytes
		return fmt.Sprintf("%s:%d",
			net.IP(rd.Value[0:4]).To4().String(),
			binary.BigEndian.Uint16(rd.Value[4:]),
		)
	case 2:
		// Type=2: 4 bytes + 2 bytes
		return fmt.Sprintf("%d:%d",
			binary.BigEndian.Uint32(rd.Value[0:4]),
			binary.BigEndian.Uint16(rd.Value[4:]),
		)
	default:
		// Should not happen with forced type, but fail-safe..
		return "unknown"
	}
}
