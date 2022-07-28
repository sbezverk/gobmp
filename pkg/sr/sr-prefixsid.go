package sr

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// PrefixSIDFlags defines PrefixSID Flag interface
type PrefixSIDFlags interface {
	GetPrefixSIDFlagByte() byte
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

func (p *PrefixSIDTLV) UnmarshalJSON(b []byte) error {
	result := &PrefixSIDTLV{}
	var objVal map[string]json.RawMessage
	if err := json.Unmarshal(b, &objVal); err != nil {
		return err
	}
	// Flags     PrefixSIDFlags `json:"flags,omitempty"`
	if v, ok := objVal["flags"]; ok {
		var flags interface{}
		if err := json.Unmarshal(v, &flags); err != nil {
			return err
		}
		if _, ok := flags.(map[string]interface{})["r_flag"]; ok {
			// ISIS flags
			f := &ISISFlags{}
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			result.Flags = f
		} else if _, ok := flags.(map[string]interface{})["np_flag"]; ok {
			// OSPF flags
			f := &OSPFFlags{}
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			result.Flags = f
		} else {
			f := &UnknownProtoFlags{}
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			result.Flags = f
		}
	}
	// Algorithm uint8          `json:"algo"`
	if v, ok := objVal["algo"]; ok {
		if err := json.Unmarshal(v, &result.Algorithm); err != nil {
			return err
		}
	}
	// SID       uint32         `json:"prefix_sid,omitempty"`
	if v, ok := objVal["prefix_sid"]; ok {
		if err := json.Unmarshal(v, &result.SID); err != nil {
			return err
		}
	}
	*p = *result

	return nil
}

// UnmarshalPrefixSIDTLV builds Prefix SID TLV Object
func UnmarshalPrefixSIDTLV(b []byte, proto base.ProtoID) (*PrefixSIDTLV, error) {
	if glog.V(6) {
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

// UnmarshalISISFlags build Prefix SID ISIS Flag Object
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

// UnmarshalOSPFFlags build Prefix SID OSPF Flag Object
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

// UnmarshalUnknownProtoFlags build Prefix SID Flag Object if protocol is neither ISIS nor OSPF
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
// ISISFlags defines a structure of ISIS Prefix SID flags
type ISISFlags struct {
	RFlag bool `json:"r_flag"`
	NFlag bool `json:"n_flag"`
	PFlag bool `json:"p_flag"`
	EFlag bool `json:"e_flag"`
	VFlag bool `json:"v_flag"`
	LFlag bool `json:"l_flag"`
}

//GetPrefixSIDFlagByte returns a byte represenation for ISIS flags
func (f *ISISFlags) GetPrefixSIDFlagByte() byte {
	b := byte(0)
	if f.RFlag {
		b += 0x80
	}
	if f.NFlag {
		b += 0x40
	}
	if f.PFlag {
		b += 0x20
	}
	if f.EFlag {
		b += 0x10
	}
	if f.VFlag {
		b += 0x08
	}
	if f.LFlag {
		b += 0x04
	}

	return b
}

// OSPF Extensions for Segment Routing RFC 8665, Section 5
// 0  1  2  3  4  5  6  7
// +--+--+--+--+--+--+--+--+
// |  |NP|M |E |V |L |  |  |
// +--+--+--+--+--+--+--+--+
// OSPFFlags defines a structure of OSPF Prefix SID flags
type OSPFFlags struct {
	NPFlag bool `json:"np_flag"`
	MFlag  bool `json:"m_flag"`
	EFlag  bool `json:"e_flag"`
	VFlag  bool `json:"v_flag"`
	LFlag  bool `json:"l_flag"`
}

//GetPrefixSIDFlagByte returns a byte represenation for OSPF flags
func (f *OSPFFlags) GetPrefixSIDFlagByte() byte {
	b := byte(0)

	if f.NPFlag {
		b += 0x40
	}
	if f.MFlag {
		b += 0x20
	}
	if f.EFlag {
		b += 0x10
	}
	if f.VFlag {
		b += 0x08
	}
	if f.LFlag {
		b += 0x04
	}

	return b
}

// UnknownProtoFlags defines a structure of Unknown protocol of Prefix SID flags
type UnknownProtoFlags struct {
	Flags byte `json:"flags"`
}

//GetPrefixSIDFlagByte returns a byte represenation for OSPF flags
func (f *UnknownProtoFlags) GetPrefixSIDFlagByte() byte {
	return f.Flags
}
