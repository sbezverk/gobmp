package sr

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

type PrefixSIDFlags interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

// PrefixSIDTLV defines Prefix SID TLV Object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.3.1
type PrefixSIDTLV struct {
	Flags     PrefixSIDFlags `json:"flags,omitempty"`
	Algorithm uint8          `json:"algo"`
	SID       uint32         `json:"prefix_sid,omitempty"`
}

func (p *PrefixSIDTLV) MarshalJSON() ([]byte, error) {
	switch p.Flags.(type) {
	case *ISISFlags:
		f := p.Flags.(*ISISFlags)
		return json.Marshal(struct {
			Flags     *ISISFlags `json:"flags,omitempty"`
			Algorithm uint8      `json:"algo"`
			SID       uint32     `json:"prefix_sid,omitempty"`
		}{
			Flags:     f,
			Algorithm: p.Algorithm,
			SID:       p.SID,
		})
	case *OSPFFlags:
		f := p.Flags.(*OSPFFlags)
		return json.Marshal(struct {
			Flags     *OSPFFlags `json:"flags,omitempty"`
			Algorithm uint8      `json:"algo"`
			SID       uint32     `json:"prefix_sid,omitempty"`
		}{
			Flags:     f,
			Algorithm: p.Algorithm,
			SID:       p.SID,
		})
	default:
		f := p.Flags.(*UnknownProtoFlags)
		return json.Marshal(struct {
			Flags     *UnknownProtoFlags `json:"flags,omitempty"`
			Algorithm uint8              `json:"algo"`
			SID       uint32             `json:"prefix_sid,omitempty"`
		}{
			Flags:     f,
			Algorithm: p.Algorithm,
			SID:       p.SID,
		})
	}
}

// UnmarshalPrefixSIDTLV builds Prefix SID TLV Object
func UnmarshalPrefixSIDTLV(b []byte, proto base.ProtoID) (*PrefixSIDTLV, error) {
	if glog.V(5) {
		glog.Infof("Prefix SID TLV Raw: %s for proto: %+v", tools.MessageHex(b), proto)
	}
	psid := PrefixSIDTLV{}
	p := 0
	switch proto {
	case base.ISISL1:
		fallthrough
	case base.ISISL2:
		f, err := UnmarshalISISFlags(b[p : p+1])
		if err != nil {
			return nil, err
		}
		psid.Flags = f
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		f, err := UnmarshalOSPFFlags(b[p : p+1])
		if err != nil {
			return nil, err
		}
		psid.Flags = f
	default:
		f, err := UnmarshalUnknownProtoFlags(b[p : p+1])
		if err != nil {
			return nil, err
		}
		psid.Flags = f
	}
	p++
	psid.Algorithm = b[p]
	p++
	// SID length would be Length of b - Flags 1 byte - Algorithm 1 byte - 2 bytes Reserved
	// If length of Prefix SID TLV 7 bytes, then SID is 20 bits label, if 8 bytes then SID is 4 bytes index
	p += 2
	s := make([]byte, 4)
	switch len(b) {
	case 7:
		copy(s[1:], b[p:p+3])
	case 8:
		copy(s, b[p:p+4])
	default:
		return nil, fmt.Errorf("invalid length %d for Prefix SID TLV", len(b))
	}
	psid.SID = binary.BigEndian.Uint32(s)

	return &psid, nil
}

// UnmarshalJSON instantiates a new instance of isis Flags object
func UnmarshalISISFlags(b []byte) (*ISISFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal Prefix Sid ISIS Flags")
	}
	nf := &ISISFlags{}
	nf.RFlag = b[0]&0x80 == 0x80
	nf.NFlag = b[0]&0x40 == 0x40
	nf.PFlag = b[0]&0x20 == 0x20
	nf.EFlag = b[0]&0x10 == 0x10
	nf.VFlag = b[0]&0x08 == 0x08
	nf.LFlag = b[0]&0x04 == 0x04

	return nf, nil
}

func UnmarshalOSPFFlags(b []byte) (*OSPFFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal Prefix Sid OSPF Flags")
	}
	nf := &OSPFFlags{}
	nf.NPFlag = b[0]&0x40 == 0x40
	nf.MFlag = b[0]&0x20 == 0x20
	nf.EFlag = b[0]&0x10 == 0x10
	nf.VFlag = b[0]&0x08 == 0x08
	nf.LFlag = b[0]&0x04 == 0x04

	return nf, nil
}

func UnmarshalUnknownProtoFlags(b []byte) (*UnknownProtoFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal Prefix Sid Flags")
	}
	nf := &UnknownProtoFlags{}
	nf.Flags = b[0]

	return nf, nil
}

//IS-IS Extensions for Segment Routing RFC 8667 Section 2.1.1.
// 0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |R|N|P|E|V|L|   |
// +-+-+-+-+-+-+-+-+
// isisFlags defines a structure of ISIS Prefix SID flags
type ISISFlags struct {
	RFlag bool `json:"r_flag"`
	NFlag bool `json:"n_flag"`
	PFlag bool `json:"p_flag"`
	EFlag bool `json:"e_flag"`
	VFlag bool `json:"v_flag"`
	LFlag bool `json:"l_flag"`
}

// MarshalJSON returns a binary representation of isis flags obeject
func (f *ISISFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RFlag bool `json:"r_flag"`
		NFlag bool `json:"n_flag"`
		PFlag bool `json:"p_flag"`
		EFlag bool `json:"e_flag"`
		VFlag bool `json:"v_flag"`
		LFlag bool `json:"l_flag"`
	}{
		RFlag: f.RFlag,
		NFlag: f.NFlag,
		PFlag: f.PFlag,
		EFlag: f.EFlag,
		VFlag: f.VFlag,
		LFlag: f.LFlag,
	})
}

// UnmarshalJSON instantiates a new instance of isis Flags object
func (f *ISISFlags) UnmarshalJSON(b []byte) error {
	type isisFlags ISISFlags
	nf := &isisFlags{}
	if err := json.Unmarshal(b, nf); err != nil {
		return err
	}
	*f = ISISFlags(*nf)

	return nil
}

// OSPF Extensions for Segment Routing RFC 8665, Section 5
// 0  1  2  3  4  5  6  7
// +--+--+--+--+--+--+--+--+
// |  |NP|M |E |V |L |  |  |
// +--+--+--+--+--+--+--+--+
// ospfFlags defines a structure of OSPF Prefix SID flags
type OSPFFlags struct {
	NPFlag bool `json:"np_flag"`
	MFlag  bool `json:"m_flag"`
	EFlag  bool `json:"e_flag"`
	VFlag  bool `json:"v_flag"`
	LFlag  bool `json:"l_flag"`
}

// MarshalJSON returns a binary representation of ospf flags obeject
func (f *OSPFFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		NPFlag bool `json:"np_flag"`
		MFlag  bool `json:"m_flag"`
		EFlag  bool `json:"e_flag"`
		VFlag  bool `json:"v_flag"`
		LFlag  bool `json:"l_flag"`
	}{
		NPFlag: f.NPFlag,
		MFlag:  f.MFlag,
		EFlag:  f.EFlag,
		VFlag:  f.VFlag,
		LFlag:  f.LFlag,
	})
}

// UnmarshalJSON instantiates a new instance of ospf Flags object
func (f *OSPFFlags) UnmarshalJSON(b []byte) error {
	type ospfFlags OSPFFlags
	nf := &ospfFlags{}
	if err := json.Unmarshal(b, nf); err != nil {
		return err
	}
	*f = OSPFFlags(*nf)

	return nil
}

type UnknownProtoFlags struct {
	Flags byte `json:"flags"`
}

// MarshalJSON returns a binary representation of ospf flags obeject
func (f *UnknownProtoFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Flags uint8 `json:"flags"`
	}{
		Flags: f.Flags,
	})
}

// UnmarshalJSON instantiates a new instance of ospf Flags object
func (f *UnknownProtoFlags) UnmarshalJSON(b []byte) error {
	type unknownProtoFlags UnknownProtoFlags
	nf := &unknownProtoFlags{}
	if err := json.Unmarshal(b, nf); err != nil {
		return err
	}
	*f = UnknownProtoFlags(*nf)
	return nil
}
