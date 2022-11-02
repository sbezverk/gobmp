package base

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// RD defines a structure of VPN prefixe's Route Distinguisher
type RD struct {
	Type  uint16
	Value []byte
}

// MakeRD instantiates a new RDs object
func MakeRD(b []byte) (*RD, error) {
	rd := RD{}
	if len(b) != 8 {
		glog.Errorf("MakeRD: invalid rd length detected in %s", tools.MessageHex(b))
		return nil, fmt.Errorf("invalid length expected 8 got %d", len(b))
	}
	rd.Type = binary.BigEndian.Uint16(b[0:2])
	if rd.Type > 2 {
		glog.Errorf("MakeRD: invalid rd type detected in %s", tools.MessageHex(b))
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
