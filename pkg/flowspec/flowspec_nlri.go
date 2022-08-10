package flowspec

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// Spec defines an interface which all types of Flowspec rules must implement
type Spec interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

// NLRI defines Flowspec NLRI structure
type NLRI struct {
	Length   uint16
	Spec     []Spec
	SpecHash string
}

// GetSpecHash returns calculated MD5 for Flowspec NLRI's Spec
func (fs *NLRI) GetSpecHash() string {
	return fs.SpecHash
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
	if glog.V(5) {
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
			fallthrough
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
		case Type10:
			fallthrough
		case Type11:
			spec, l, err = makeGenericSpec(b[p:])
			if err != nil {
				return nil, err
			}
		case Type9:
			fallthrough
		case Type12:
			return nil, fmt.Errorf("not implemented Flowspec type: %+v", t)
		default:
			return nil, fmt.Errorf("unknown Flowspec type: %+v", t)
		}
		fs.Spec = append(fs.Spec, spec)
		p += l
	}

	// Calculating hash of all recovered spec
	sp, err := json.Marshal(fs.Spec)
	if err != nil {
		return nil, err
	}
	s := md5.Sum(sp)
	fs.SpecHash = hex.EncodeToString(s[:])

	return fs, nil
}

// Operator defines a data structure representing Flowspec operator byte
type Operator struct {
	EOLBit bool
	ANDBit bool
	Length uint8
	LTBit  bool
	GTBit  bool
	EQBit  bool
}

// UnmarshalFlowspecOperator creates an instance of Operator object from a byte
func UnmarshalFlowspecOperator(b byte) (*Operator, error) {
	o := &Operator{}
	if b&0x80 == 0x80 {
		o.EOLBit = true
	}
	if b&0x40 == 0x40 {
		o.ANDBit = true
	}
	l := (b & 0x30) >> 4
	o.Length = 1 << l
	if b&0x04 == 0x04 {
		o.LTBit = true
	}
	if b&0x02 == 0x02 {
		o.GTBit = true
	}
	if b&0x01 == 0x01 {
		o.EQBit = true
	}

	return o, nil
}

// MarshalJSON returns a binary representation of Flowspec Operator structure
func (o *Operator) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		EOLBit bool  `json:"end_of_list_bit,omitempty"`
		ANDBit bool  `json:"and_bit,omitempty"`
		Length uint8 `json:"value_length,omitempty"`
		LTBit  bool  `json:"less_than,omitempty"`
		GTBit  bool  `json:"greater_than,omitempty"`
		EQBit  bool  `json:"equal,omitempty"`
	}{
		EOLBit: o.EOLBit,
		ANDBit: o.ANDBit,
		Length: o.Length,
		LTBit:  o.LTBit,
		GTBit:  o.GTBit,
		EQBit:  o.EQBit,
	})

}

// UnmarshalJSON creates a new instance of Flowspec Operator
func (o *Operator) UnmarshalJSON(b []byte) error {
	t := &Operator{}
	if err := json.Unmarshal(b, t); err != nil {
		return err
	}
	o = t

	return nil
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
	s.PrefixLength = b[p]
	l := int(s.PrefixLength / 8)
	if b[p]%8 != 0 {
		l++
	}
	p++
	s.Prefix = make([]byte, l)
	copy(s.Prefix, b[p:p+l])
	p += int(l)

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

// OpVal defines structure of Operator and Value pair
type OpVal struct {
	Op  *Operator `json:"operator,omitempty"`
	Val []byte    `json:"value,omitempty"`
}

// UnmarshalJSON unmarshals a slice of bytes into a new Operator/Value pair
func (o *OpVal) UnmarshalJSON(b []byte) error {
	ov := &OpVal{}
	if err := json.Unmarshal(b, ov); err != nil {
		return err
	}
	o = ov

	return nil
}

// MarshalJSON returns a binary representation of FlowSPec PrefixSpec
func (o *OpVal) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Op  *Operator `json:"operator,omitempty"`
		Val []byte    `json:"value,omitempty"`
	}{
		Op:  o.Op,
		Val: o.Val,
	})
}

// UnmarshalOpVal creates a slice of Operator/Value pairs
func UnmarshalOpVal(b []byte) ([]*OpVal, error) {
	opvals := make([]*OpVal, 0)
	p := 0
	// Skip type
	p++
	eol := false
	for !eol && p < len(b) {
		o, err := UnmarshalFlowspecOperator(b[p])
		if err != nil {
			return nil, err
		}
		p++
		if p+int(o.Length) > len(b) {
			return nil, fmt.Errorf("not enough bytes to unmarshal Operator/Value pair")
		}
		opval := &OpVal{
			Op:  o,
			Val: make([]byte, o.Length),
		}
		copy(opval.Val, b[p:p+int(o.Length)])
		opvals = append(opvals, opval)
		p += int(o.Length)
		if o.EOLBit {
			eol = true
		}
	}

	return opvals, nil
}

// GenericSpec defines a structure of Flowspec Types (3,4,5,6,7,8,10,11) specs.
type GenericSpec struct {
	SpecType uint8    `json:"type,omitempty"`
	OpVal    []*OpVal `json:"op_val_pairs,omitempty"`
}

func makeGenericSpec(b []byte) (Spec, int, error) {
	s := &GenericSpec{}
	var err error
	p := 0
	s.SpecType = b[p]
	p++
	s.OpVal, err = UnmarshalOpVal(b)
	if err != nil {
		return nil, 0, err
	}
	// Calculate total Spec length
	for _, ov := range s.OpVal {
		if ov == nil {
			continue
		}
		// Operator length of Operator/Value pair - 1 byte
		p++
		// Value length of Operator/Value pair
		p += int(ov.Op.Length)
	}

	return s, p, nil
}

// UnmarshalJSON unmarshals a slice of bytes into a new FlowSPec GenericSpec
func (t *GenericSpec) UnmarshalJSON(b []byte) error {
	s := &GenericSpec{}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	t = s

	return nil
}

// MarshalJSON returns a binary representation of FlowSPec GenericSpec
func (t *GenericSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SpecType uint8    `json:"type,omitempty"`
		OpVal    []*OpVal `json:"op_val_pairs,omitempty"`
	}{
		SpecType: t.SpecType,
		OpVal:    t.OpVal,
	})
}
