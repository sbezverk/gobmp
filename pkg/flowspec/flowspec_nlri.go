package flowspec

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// Spec defines an interface which all types of Flowspec rules must implement.
type Spec interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

// NLRI defines Flowspec NLRI structure.
// RD is populated only for VPN FlowSpec (SAFI=134) per RFC 8955 Section 6.
type NLRI struct {
	Length   uint16
	Spec     []Spec
	SpecHash string
	RD       string `json:"rd,omitempty"`
}

// GetSpecHash returns calculated MD5 for Flowspec NLRI's Spec.
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

// parseFlowspecSpecs parses the filter spec portion of a FlowSpec NLRI (no length prefix, no RD).
// Set ipv6=true for IPv6 FlowSpec (RFC 8956) prefix encoding with offset field.
func parseFlowspecSpecs(b []byte, ipv6 bool) ([]Spec, error) {
	var specs []Spec
	p := 0
	for p < len(b) {
		t := b[p]
		l := 0
		var spec Spec
		var err error
		switch SpecType(t) {
		case Type1:
			fallthrough
		case Type2:
			if ipv6 {
				spec, l, err = makeIPv6PrefixSpec(b[p:])
			} else {
				spec, l, err = makePrefixSpec(b[p:])
			}
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
			spec, l, err = makeGenericSpec(b[p:])
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown Flowspec type: %+v", t)
		}
		if l == 0 {
			return nil, fmt.Errorf("spec parser returned zero-length advance at offset %d, type %d", p, t)
		}
		specs = append(specs, spec)
		p += l
	}
	return specs, nil
}

// computeSpecHash calculates an MD5 hash of raw spec bytes with a namespace prefix byte.
// Using raw bytes avoids the json.Marshal allocation on the hot path.
func computeSpecHash(rawSpecs []byte, afiByte byte) string {
	h := md5.New()
	h.Write([]byte{afiByte})
	h.Write(rawSpecs)
	return hex.EncodeToString(h.Sum(nil))
}

// unmarshalSingleFlowspecNLRI parses a single Flowspec NLRI starting at b[0].
// It reads the length prefix, parses all filter specs within that NLRI, and
// returns the NLRI plus the total number of bytes consumed (including the length field).
// Set ipv6=true for IPv6 FlowSpec (RFC 8956) prefix encoding with offset field.
func unmarshalSingleFlowspecNLRI(b []byte, ipv6 bool) (*NLRI, int, error) {
	if len(b) == 0 {
		return nil, 0, fmt.Errorf("NLRI length is 0")
	}
	fs := &NLRI{}
	p := 0
	if b[p]&0xf0 == 0xf0 {
		// NLRI length is encoded into 2 bytes (RFC 8955 Section 4)
		if len(b) < 2 {
			return nil, 0, fmt.Errorf("need 2 bytes for extended NLRI length, have %d", len(b))
		}
		fs.Length = ((uint16(b[p]) & 0x0f) << 8) | uint16(b[p+1])
		p += 2
	} else {
		fs.Length = uint16(b[p])
		p++
	}
	if fs.Length == 0 {
		return nil, 0, fmt.Errorf("invalid zero-length Flowspec NLRI")
	}
	end := p + int(fs.Length)
	if end > len(b) {
		return nil, 0, fmt.Errorf("not enough bytes to unmarshal flowspec NLRI: need %d bytes, have %d", fs.Length, len(b)-p)
	}
	specStart := p
	specs, err := parseFlowspecSpecs(b[p:end], ipv6)
	if err != nil {
		return nil, 0, err
	}
	fs.Spec = specs

	afiByte := byte(1)
	if ipv6 {
		afiByte = 2
	}
	fs.SpecHash = computeSpecHash(b[specStart:end], afiByte)

	return fs, end, nil
}

// unmarshalSingleVPNFlowspecNLRI parses a single VPN FlowSpec NLRI (SAFI=134) per RFC 8955 Section 6.
// The NLRI payload starts with an 8-byte Route Distinguisher followed by standard FlowSpec specs.
func unmarshalSingleVPNFlowspecNLRI(b []byte, ipv6 bool) (*NLRI, int, error) {
	if len(b) == 0 {
		return nil, 0, fmt.Errorf("NLRI length is 0")
	}
	fs := &NLRI{}
	p := 0
	if b[p]&0xf0 == 0xf0 {
		if len(b) < 2 {
			return nil, 0, fmt.Errorf("need 2 bytes for extended NLRI length, have %d", len(b))
		}
		fs.Length = ((uint16(b[p]) & 0x0f) << 8) | uint16(b[p+1])
		p += 2
	} else {
		fs.Length = uint16(b[p])
		p++
	}
	if fs.Length == 0 {
		return nil, 0, fmt.Errorf("invalid zero-length VPN Flowspec NLRI")
	}
	end := p + int(fs.Length)
	if end > len(b) {
		return nil, 0, fmt.Errorf("not enough bytes to unmarshal VPN flowspec NLRI: need %d bytes, have %d", fs.Length, len(b)-p)
	}
	// RFC 8955 Section 6: First 8 bytes of payload are the Route Distinguisher.
	if end-p < 8 {
		return nil, 0, fmt.Errorf("VPN Flowspec NLRI too short for Route Distinguisher: need 8 bytes, have %d", end-p)
	}
	rd, err := base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse Route Distinguisher: %w", err)
	}
	fs.RD = rd.String()
	p += 8

	specStart := p
	specs, err := parseFlowspecSpecs(b[p:end], ipv6)
	if err != nil {
		return nil, 0, fmt.Errorf("VPN FlowSpec (RD=%s): %w", fs.RD, err)
	}
	fs.Spec = specs

	// Namespace VPN hashes by RD + AFI to avoid collisions across VRFs.
	h := md5.New()
	h.Write([]byte(fs.RD))
	if ipv6 {
		h.Write([]byte{2})
	} else {
		h.Write([]byte{1})
	}
	h.Write(b[specStart:end])
	fs.SpecHash = hex.EncodeToString(h.Sum(nil))

	return fs, end, nil
}

// UnmarshalFlowspecNLRI creates an instance of IPv4 Flowspec NLRI from a slice of bytes.
// It parses only the first NLRI in the slice and logs a warning if trailing data
// exists. Use UnmarshalAllFlowspecNLRI for multi-NLRI support (RFC 8955 Section 4).
func UnmarshalFlowspecNLRI(b []byte) (*NLRI, error) {
	if glog.V(5) {
		glog.Infof("Flowspec NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	fs, consumed, err := unmarshalSingleFlowspecNLRI(b, false)
	if err != nil {
		return nil, err
	}
	if consumed < len(b) {
		if glog.V(5) {
			glog.Infof("UnmarshalFlowspecNLRI: %d trailing bytes ignored (multiple NLRIs), use UnmarshalAllFlowspecNLRI", len(b)-consumed)
		}
	}
	return fs, nil
}

// UnmarshalIPv6FlowspecNLRI creates an instance of IPv6 Flowspec NLRI from a slice of bytes.
// Uses RFC 8956 §3 prefix encoding with offset field. Parses only the first NLRI.
func UnmarshalIPv6FlowspecNLRI(b []byte) (*NLRI, error) {
	if glog.V(5) {
		glog.Infof("Flowspec IPv6 NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	fs, consumed, err := unmarshalSingleFlowspecNLRI(b, true)
	if err != nil {
		return nil, err
	}
	if consumed < len(b) {
		if glog.V(5) {
			glog.Infof("UnmarshalIPv6FlowspecNLRI: %d trailing bytes ignored (multiple NLRIs), use UnmarshalAllIPv6FlowspecNLRI", len(b)-consumed)
		}
	}
	return fs, nil
}

// UnmarshalAllFlowspecNLRI parses one or more IPv4 Flowspec NLRIs from a byte slice
// as specified in RFC 8955 Section 4.
func UnmarshalAllFlowspecNLRI(b []byte) ([]*NLRI, error) {
	return unmarshalAllFlowspecNLRIWithAF(b, false)
}

// UnmarshalAllIPv6FlowspecNLRI parses one or more IPv6 Flowspec NLRIs from a byte slice
// as specified in RFC 8956 Section 3. IPv6 prefix types use an additional offset field.
func UnmarshalAllIPv6FlowspecNLRI(b []byte) ([]*NLRI, error) {
	return unmarshalAllFlowspecNLRIWithAF(b, true)
}

func unmarshalAllFlowspecNLRIWithAF(b []byte, ipv6 bool) ([]*NLRI, error) {
	if glog.V(5) {
		glog.Infof("Flowspec NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, nil
	}
	var result []*NLRI
	p := 0
	for p < len(b) {
		fs, consumed, err := unmarshalSingleFlowspecNLRI(b[p:], ipv6)
		if err != nil {
			return nil, fmt.Errorf("NLRI at offset %d: %w", p, err)
		}
		result = append(result, fs)
		p += consumed
	}
	return result, nil
}

// UnmarshalVPNFlowspecNLRI parses a single VPN FlowSpec NLRI (SAFI=134) per RFC 8955 Section 6.
// The NLRI payload is prefixed with an 8-byte Route Distinguisher before the FlowSpec filter specs.
// Set ipv6=true for AFI=2 (IPv6 prefix encoding with offset field per RFC 8956).
func UnmarshalVPNFlowspecNLRI(b []byte, ipv6 bool) (*NLRI, error) {
	if glog.V(5) {
		glog.Infof("VPN Flowspec NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	fs, consumed, err := unmarshalSingleVPNFlowspecNLRI(b, ipv6)
	if err != nil {
		return nil, err
	}
	if consumed < len(b) {
		if glog.V(5) {
			glog.Infof("UnmarshalVPNFlowspecNLRI: %d trailing bytes ignored (multiple NLRIs), use UnmarshalAllVPNFlowspecNLRI", len(b)-consumed)
		}
	}
	return fs, nil
}

// UnmarshalAllVPNFlowspecNLRI parses one or more VPN FlowSpec NLRIs (SAFI=134) per RFC 8955 Section 6.
// Returns nil slice with nil error for empty input (withdraw-all signal).
func UnmarshalAllVPNFlowspecNLRI(b []byte, ipv6 bool) ([]*NLRI, error) {
	if glog.V(5) {
		glog.Infof("VPN Flowspec NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, nil
	}
	var result []*NLRI
	p := 0
	for p < len(b) {
		fs, consumed, err := unmarshalSingleVPNFlowspecNLRI(b[p:], ipv6)
		if err != nil {
			return nil, fmt.Errorf("VPN NLRI at offset %d: %w", p, err)
		}
		result = append(result, fs)
		p += consumed
	}
	return result, nil
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
	// Use type alias to avoid infinite recursion
	type Alias Operator
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(o),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	return nil
}

// PrefixSpec defines a structure of Flowspec Type 1 and Type 2 (Destination/Source Prefix) spec.
// For IPv4 FlowSpec (RFC 8955), Offset is always 0.
// For IPv6 FlowSpec (RFC 8956 Section 3), Offset specifies how many leading prefix bits to ignore.
type PrefixSpec struct {
	SpecType     uint8  `json:"type"`
	PrefixLength uint8  `json:"prefix_len"`
	Offset       uint8  `json:"prefix_offset,omitempty"`
	Prefix       []byte `json:"prefix"`
}

func makePrefixSpec(b []byte) (Spec, int, error) {
	if len(b) < 2 {
		return nil, 0, fmt.Errorf("insufficient data for prefix spec: need at least 2 bytes, got %d", len(b))
	}
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
	if p+l > len(b) {
		return nil, 0, fmt.Errorf("insufficient data for prefix spec: need %d bytes, got %d", p+l, len(b))
	}
	s.Prefix = make([]byte, l)
	copy(s.Prefix, b[p:p+l])
	p += int(l)

	return s, p, nil
}

// makeIPv6PrefixSpec parses an IPv6 FlowSpec prefix filter (RFC 8956 Section 3).
// Format: Type(1) + PrefixLength(1) + Offset(1) + Prefix(ceil((PrefixLength-Offset)/8))
func makeIPv6PrefixSpec(b []byte) (Spec, int, error) {
	if len(b) < 3 {
		return nil, 0, fmt.Errorf("not enough bytes for IPv6 prefix spec: need 3, have %d", len(b))
	}
	s := &PrefixSpec{}
	p := 0
	s.SpecType = b[p]
	p++
	s.PrefixLength = b[p]
	p++
	s.Offset = b[p]
	p++
	// RFC 8956 Section 3: prefix bytes encode (PrefixLength - Offset) significant bits
	bits := int(s.PrefixLength) - int(s.Offset)
	if bits < 0 {
		return nil, 0, fmt.Errorf("IPv6 prefix offset %d exceeds prefix length %d", s.Offset, s.PrefixLength)
	}
	l := bits / 8
	if bits%8 != 0 {
		l++
	}
	if p+l > len(b) {
		return nil, 0, fmt.Errorf("not enough bytes for IPv6 prefix: need %d, have %d", l, len(b)-p)
	}
	s.Prefix = make([]byte, l)
	copy(s.Prefix, b[p:p+l])
	p += l

	return s, p, nil
}

// UnmarshalJSON unmarshals a slice of bytes into a new FlowSPec PrefixSpec
func (t *PrefixSpec) UnmarshalJSON(b []byte) error {
	// Use type alias to avoid infinite recursion
	type Alias PrefixSpec
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(t),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	return nil
}

// MarshalJSON returns a binary representation of FlowSPec PrefixSpec.
func (t *PrefixSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SpecType     uint8  `json:"type"`
		PrefixLength uint8  `json:"prefix_len"`
		Offset       uint8  `json:"prefix_offset,omitempty"`
		Prefix       []byte `json:"prefix"`
	}{
		SpecType:     t.SpecType,
		PrefixLength: t.PrefixLength,
		Offset:       t.Offset,
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
	// Use type alias to avoid infinite recursion
	type Alias OpVal
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(o),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

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
	if len(b) < 2 {
		return nil, fmt.Errorf("input too short for operator/value sequence: need at least 2 bytes, got %d", len(b))
	}
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
	if !eol {
		return nil, fmt.Errorf("operator/value sequence ended at offset %d without EOL bit set", p)
	}

	return opvals, nil
}

// GenericSpec defines a structure of Flowspec Types 3-12 (operator/value) specs.
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
	// Use type alias to avoid infinite recursion
	type Alias GenericSpec
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(t),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

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
