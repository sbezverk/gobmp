package sr

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// AdjacencySIDFlag defines Adjecency SID Flag interface
type AdjacencySIDFlags interface {
	GetAdjSIDFlagByte() byte
}

// AdjacencySIDTLV defines Adjacency SID TLV Object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.2.1
type AdjacencySIDTLV struct {
	Flags  AdjacencySIDFlags `json:"flags,omitempty"`
	Weight uint8             `json:"weight"`
	SID    uint32            `json:"sid,omitempty"`
}

func (a *AdjacencySIDTLV) MarshalJSON() ([]byte, error) {
	switch a.Flags.(type) {
	case *AdjISISFlags:
		f := a.Flags.(*AdjISISFlags)
		return json.Marshal(struct {
			Flags  *AdjISISFlags `json:"flags,omitempty"`
			Weight uint8         `json:"weight"`
			SID    uint32        `json:"sid,omitempty"`
		}{
			Flags:  f,
			Weight: a.Weight,
			SID:    a.SID,
		})
	case *AdjOSPFFlags:
		f := a.Flags.(*AdjOSPFFlags)
		return json.Marshal(struct {
			Flags  *AdjOSPFFlags `json:"flags,omitempty"`
			Weight uint8         `json:"weight"`
			SID    uint32        `json:"sid,omitempty"`
		}{
			Flags:  f,
			Weight: a.Weight,
			SID:    a.SID,
		})
	default:
		f := a.Flags.(*UnknownProtoFlags)
		return json.Marshal(struct {
			Flags  *UnknownProtoFlags `json:"flags,omitempty"`
			Weight uint8              `json:"weight"`
			SID    uint32             `json:"sid,omitempty"`
		}{
			Flags:  f,
			Weight: a.Weight,
			SID:    a.SID,
		})
	}
}

func (a *AdjacencySIDTLV) UnmarshalJSON(b []byte) error {
	result := &AdjacencySIDTLV{}
	var objVal map[string]json.RawMessage
	if err := json.Unmarshal(b, &objVal); err != nil {
		return err
	}
	// Flags  AdjacencySIDFlags `json:"flags,omitempty"`
	if v, ok := objVal["flags"]; ok {
		var flags interface{}
		if err := json.Unmarshal(v, &flags); err != nil {
			return err
		}
		if _, ok := flags.(map[string]interface{})["f_flag"]; ok {
			// ISIS flags
			f := &AdjISISFlags{}
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			result.Flags = f
		} else if _, ok := flags.(map[string]interface{})["g_flag"]; ok {
			// OSPF flags
			f := &AdjOSPFFlags{}
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
	if v, ok := objVal["weight"]; ok {
		if err := json.Unmarshal(v, &result.Weight); err != nil {
			return err
		}
	}
	// SID       uint32         `json:"sid,omitempty"`
	if v, ok := objVal["sid"]; ok {
		if err := json.Unmarshal(v, &result.SID); err != nil {
			return err
		}
	}
	*a = *result

	return nil
}

// UnmarshalAdjacencySIDTLV builds Adjacency SID TLV Object
func UnmarshalAdjacencySIDTLV(b []byte, proto base.ProtoID) (*AdjacencySIDTLV, error) {
	if glog.V(6) {
		glog.Infof("Adjacency SID TLV Raw: %s for proto: %+v", tools.MessageHex(b), proto)
	}
	asid := AdjacencySIDTLV{}
	p := 0
	switch proto {
	case base.ISISL1:
		fallthrough
	case base.ISISL2:
		f, err := UnmarshalAdjISISFlags(b[p : p+1])
		if err != nil {
			return nil, err
		}
		asid.Flags = f
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		f, err := UnmarshalAdjOSPFFlags(b[p : p+1])
		if err != nil {
			return nil, err
		}
		asid.Flags = f
	default:
		f, err := UnmarshalUnknownProtoFlags(b[p : p+1])
		if err != nil {
			return nil, err
		}
		asid.Flags = f
	}
	p++
	asid.Weight = b[p]
	p++
	// SID length would be Length of b - Flags 1 byte - Algorithm 1 byte - 2 bytes Reserved
	// If length of Adjacency SID TLV 7 bytes, then SID is 20 bits label, if 8 bytes then SID is 4 bytes index
	p += 2
	s := make([]byte, 4)
	switch len(b) {
	case 7:
		copy(s[1:], b[p:p+3])
	case 8:
		copy(s, b[p:p+4])
	default:
		return nil, fmt.Errorf("invalid length %d for Adjacency SID TLV", len(b))
	}
	asid.SID = binary.BigEndian.Uint32(s)

	return &asid, nil
}

// UnmarshalISISFlags build Adjacency SID ISIS Flag Object
func UnmarshalAdjISISFlags(b []byte) (*AdjISISFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal Adjacency Sid ISIS Flags")
	}
	nf := &AdjISISFlags{}
	nf.FFlag = b[0]&0x80 == 0x80
	nf.BFlag = b[0]&0x40 == 0x40
	nf.VFlag = b[0]&0x20 == 0x20
	nf.LFlag = b[0]&0x10 == 0x10
	nf.SFlag = b[0]&0x08 == 0x08
	nf.PFlag = b[0]&0x04 == 0x04

	return nf, nil
}

// UnmarshalOSPFFlags build Adjacency SID OSPF Flag Object
func UnmarshalAdjOSPFFlags(b []byte) (*AdjOSPFFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal Adjacency Sid OSPF Flags")
	}
	nf := &AdjOSPFFlags{}
	nf.BFlag = b[0]&0x80 == 0x80
	nf.VFlag = b[0]&0x40 == 0x40
	nf.LFlag = b[0]&0x20 == 0x20
	nf.GFlag = b[0]&0x10 == 0x10
	nf.PFlag = b[0]&0x08 == 0x08

	return nf, nil
}

// https://www.rfc-editor.org/rfc/rfc8667.html#section-2.2.1
// 0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |F|B|V|L|S|P|   |
// +-+-+-+-+-+-+-+-+
// ISISFlags defines a structure of ISIS Adjacency SID flags
type AdjISISFlags struct {
	FFlag bool `json:"f_flag"`
	BFlag bool `json:"b_flag"`
	VFlag bool `json:"v_flag"`
	LFlag bool `json:"l_flag"`
	SFlag bool `json:"s_flag"`
	PFlag bool `json:"p_flag"`
}

//GetAdjSIDFlagByte returns a byte represenation for ISIS flags
func (f *AdjISISFlags) GetAdjSIDFlagByte() byte {
	b := byte(0)
	if f.FFlag {
		b += 0x80
	}
	if f.BFlag {
		b += 0x40
	}
	if f.VFlag {
		b += 0x20
	}
	if f.LFlag {
		b += 0x10
	}
	if f.SFlag {
		b += 0x08
	}
	if f.PFlag {
		b += 0x04
	}

	return b
}

// https://www.rfc-editor.org/rfc/rfc8665.html#section-6.1
// https://www.rfc-editor.org/rfc/rfc8666.html#section-7.1
// 0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |B|V|L|G|P|     |
// +-+-+-+-+-+-+-+-+
// OSPFFlags defines a structure of OSPF Adjacency SID flags
type AdjOSPFFlags struct {
	BFlag bool `json:"b_flag"`
	VFlag bool `json:"v_flag"`
	LFlag bool `json:"l_flag"`
	GFlag bool `json:"g_flag"`
	PFlag bool `json:"p_flag"`
}

//GetAdjSIDFlagByte returns a byte represenation for OSPF flags
func (f *AdjOSPFFlags) GetAdjSIDFlagByte() byte {
	b := byte(0)

	if f.BFlag {
		b += 0x80
	}
	if f.VFlag {
		b += 0x40
	}
	if f.LFlag {
		b += 0x20
	}
	if f.GFlag {
		b += 0x10
	}
	if f.PFlag {
		b += 0x08
	}

	return b
}

//GetAdjSIDFlagByte returns a byte represenation for an Unknown Protocol
func (f *UnknownProtoFlags) GetAdjSIDFlagByte() byte {
	return f.Flags
}
