package flowspec

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Spec defines an interface which all types of Flowspec rules must implement
type Spec interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

// NLRI defines Flowspec NLRI structure
type NLRI struct {
	Length uint16
	Spec   []Spec
}

type SpecType uint8

const (
	// Type1 defines Flowspec Specification type for Destination Prefix
	Type1 SpecType = 1
	// Type2 defines Flowspec Specification type for Source Prefix
	Type2 SpecType = 2
	// Type3 defines Flowspec Specification type for IP Protocol
	Type3 SpecType = 3
	// Type4 defines Flowspec Specification type for Port
	Type4 SpecType = 4
	// Type5 defines Flowspec Specification type for Destination port
	Type5 SpecType = 5
	// Type6 defines Flowspec Specification type for Source port
	Type6 SpecType = 6
	// Type7 defines Flowspec Specification type for ICMP type
	Type7 SpecType = 7
	// Type8 defines Flowspec Specification type for ICMP code
	Type8 SpecType = 8
	// Type9 defines Flowspec Specification type for TCP flags
	Type9 SpecType = 9
	// Type10 defines Flowspec Specification type for Packet length
	Type10 SpecType = 10
	// Type11 defines Flowspec Specification type for DSCP (Diffserv Code Point)
	Type11 SpecType = 11
	// Type12 defines Flowspec Specification type for Fragment
	Type12 SpecType = 12
)

// UnmarshalFlowspecNLRI creates an instance of Flowspec NLRI from a slice of bytes
func UnmarshalFlowspecNLRI(b []byte) (*NLRI, error) {
	if glog.V(6) {
		glog.Infof("Flowspec NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	fs := &NLRI{}
	p := 0
	if b[p]&0xf0 == 0xf0 {
		// NLRI length is encoded into 2 bytes
		binary.BigEndian.PutUint16(b[p:p+2], fs.Length)
		p += 2
	} else {
		// Otherwise it is encoded in the single byte
		fs.Length = uint16(b[p])
		p++
	}
	if p+int(fs.Length) != len(b) {
		return nil, fmt.Errorf("invalid length encoded length %d does not match with slice length %d", fs.Length, len(b))
	}
	for p < len(b) {
		t := b[p]
		switch SpecType(t) {
		case Type1:
		case Type2:
		case Type3:
		case Type4:
		case Type5:
		case Type6:
		case Type7:
		case Type8:
		case Type9:
		case Type10:
		case Type11:
		case Type12:
		default:
			return nil, fmt.Errorf("unknown Flowspec type: %+v", t)
		}
	}

	return fs, nil
}
