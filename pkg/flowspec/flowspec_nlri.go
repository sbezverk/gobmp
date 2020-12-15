package flowspec

import (
	"encoding/binary"
	"encoding/json"
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

// SpecType defines Flowspec Spec type
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
		l := 0
		var spec Spec
		var err error
		switch SpecType(t) {
		case Type1:
			spec, l, err = makePrefixSpec(b[p:])
			if err != nil {
				return nil, err
			}
		case Type2:
			spec, l, err = makePrefixSpec(b[p:])
			if err != nil {
				return nil, err
			}
		case Type3:
			fallthrough
		case Type4:
			fallthrough
		case Type5:
			fallthrough
		case Type6:
			fallthrough
		case Type7:
			fallthrough
		case Type8:
			fallthrough
		case Type9:
			fallthrough
		case Type10:
			fallthrough
		case Type11:
			fallthrough
		case Type12:
			return nil, fmt.Errorf("not implemented Flowspec type: %+v", t)
		default:
			return nil, fmt.Errorf("unknown Flowspec type: %+v", t)
		}
		fs.Spec = append(fs.Spec, spec)
		p += l
	}

	return fs, nil
}

// PrefixSpec defines a structure of Flowspec Type 1 and Type 2 (Destination/Source Prefix) spec.
type PrefixSpec struct {
	SpecType     uint8  `json:"type"`
	PrefixLength uint8  `json:"prefix_len"`
	Prefix       []byte `json:"prefix"`
}

func makePrefixSpec(b []byte) (Spec, int, error) {
	s := &PrefixSpec{}
	p := 0
	s.SpecType = b[p]
	p++
	s.PrefixLength = b[p] / 8
	if b[p]%8 != 0 {
		s.PrefixLength++
	}
	p++
	s.Prefix = make([]byte, s.PrefixLength)
	copy(s.Prefix, b[p:p+int(s.PrefixLength)])
	p += int(s.PrefixLength)

	return s, p, nil
}

// UnmarshalJSON unmarshals a slice of bytes into a new FlowSPec PrefixSpec
func (t *PrefixSpec) UnmarshalJSON(b []byte) error {
	s := &PrefixSpec{}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	t = s

	return nil
}

// MarshalJSON returns a binary representation of FlowSPec PrefixSpec
func (t *PrefixSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SpecType     uint8  `json:"type"`
		PrefixLength uint8  `json:"prefix_len"`
		Prefix       []byte `json:"prefix"`
	}{
		SpecType:     t.SpecType,
		PrefixLength: t.PrefixLength,
		Prefix:       t.Prefix,
	})
}
