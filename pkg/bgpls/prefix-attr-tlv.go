package bgpls

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/tools"
)

// PrefixAttrTLVs defines a struvture for Prefix Attributes as defined in the following RFC proposal:
// https://datatracker.ietf.org/doc/html/draft-ietf-idr-bgp-ls-segment-routing-ext-17#section-2.3
type PrefixAttrTLVs struct {
	LSPrefixSID    []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
	Range          *RangeTLV          `json:"range,omitempty"`          // RFC 9085 Section 2.3.5
	Flags          PrefixAttrFlags    `json:"flags,omitempty"`
	SourceRouterID string             `json:"source_router_id,omitempty"` // RFC 9085 Section 2.3.4 - TLV 1174 (OSPF) or TLV 1171 (generic)
}

// PrefixAttrFlags defines Prefix Attribute Flags interface
type PrefixAttrFlags interface {
	GetPrefixAttrFlagsByte() byte
}

func (p *PrefixAttrTLVs) MarshalJSON() ([]byte, error) {
	// Do not want to return instantiated but empty object if non of attributes present
	// returning instantiated object if there is at least 1 initialized attribute.
	if len(p.LSPrefixSID) == 0 && p.Flags == nil && p.SourceRouterID == "" {
		return nil, nil
	}
	switch p.Flags.(type) {
	case *ISISFlags:
		f := p.Flags.(*ISISFlags)
		return json.Marshal(struct {
			LSPrefixSID    []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
			Flags          *ISISFlags         `json:"flags,omitempty"`
			SourceRouterID string             `json:"source_router_id,omitempty"`
		}{
			Flags:          f,
			LSPrefixSID:    p.LSPrefixSID,
			SourceRouterID: p.SourceRouterID,
		})
	case *OSPFFlags:
		f := p.Flags.(*OSPFFlags)
		return json.Marshal(struct {
			LSPrefixSID    []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
			Flags          *OSPFFlags         `json:"flags,omitempty"`
			SourceRouterID string             `json:"source_router_id,omitempty"`
		}{
			Flags:          f,
			LSPrefixSID:    p.LSPrefixSID,
			SourceRouterID: p.SourceRouterID,
		})
	case *UnknownProtoFlags:
		f := p.Flags.(*UnknownProtoFlags)
		return json.Marshal(struct {
			LSPrefixSID    []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
			Flags          *UnknownProtoFlags `json:"flags,omitempty"`
			SourceRouterID string             `json:"source_router_id,omitempty"`
		}{
			Flags:          f,
			LSPrefixSID:    p.LSPrefixSID,
			SourceRouterID: p.SourceRouterID,
		})
	default:
		return json.Marshal(struct {
			LSPrefixSID    []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
			SourceRouterID string             `json:"source_router_id,omitempty"`
		}{
			LSPrefixSID:    p.LSPrefixSID,
			SourceRouterID: p.SourceRouterID,
		})
	}
}

func (p *PrefixAttrTLVs) UnmarshalJSON(b []byte) error {
	result := &PrefixAttrTLVs{}
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
		// Presence of `x_flag` indicates ISIS's flags structure
		if _, ok := flags.(map[string]interface{})["x_flag"]; ok {
			f := &ISISFlags{}
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			result.Flags = f
			// Presence of `a_flag` indicates OSPF's flags structure
		} else if _, ok := flags.(map[string]interface{})["a_flag"]; ok {
			f := &OSPFFlags{}
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			result.Flags = f
			// Presence of `a_flag` indicates OSPFv3's flags structure
		} else if _, ok := flags.(map[string]interface{})["nu_flag"]; ok {
			f := &OSPFv3Flags{}
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
	// LSPrefixSID    []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
	if v, ok := objVal["ls_prefix_sid"]; ok {
		if err := json.Unmarshal(v, &result.LSPrefixSID); err != nil {
			return err
		}
	}
	// SourceRouterID string             `json:"source_router_id,omitempty"`
	if v, ok := objVal["source_router_id"]; ok {
		if err := json.Unmarshal(v, &result.SourceRouterID); err != nil {
			return err
		}
	}
	*p = *result

	return nil
}

// UnmarshalPrefixSIDTLV builds Prefix SID TLV Object
func UnmarshalPrefixAttrFlags(b []byte, proto base.ProtoID) (PrefixAttrFlags, error) {
	if glog.V(6) {
		glog.Infof("Prefix Attr Flags Raw: %s for proto: %+v", tools.MessageHex(b), proto)
	}
	p := 0
	switch proto {
	case base.ISISL1:
		fallthrough
	case base.ISISL2:
		return UnmarshalISISFlags(b[p : p+1])
	case base.OSPFv2:
		return UnmarshalOSPFFlags(b[p : p+1])
	case base.OSPFv3:
		return UnmarshalOSPFv3Flags(b[p : p+1])
	default:
		return UnmarshalUnknownProtoFlags(b[p : p+1])
	}
}

// UnmarshalISISFlags build Prefix SID ISIS Flag Object
func UnmarshalISISFlags(b []byte) (*ISISFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal Prefix Attr ISIS Flags")
	}
	nf := &ISISFlags{}
	nf.XFlag = b[0]&0x80 == 0x80
	nf.RFlag = b[0]&0x40 == 0x40
	nf.NFlag = b[0]&0x20 == 0x20

	return nf, nil
}

// UnmarshalOSPFFlags build Prefix Attr OSPF Flags Object
func UnmarshalOSPFFlags(b []byte) (*OSPFFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal Prefix Attr OSPF Flags")
	}
	nf := &OSPFFlags{}
	nf.AFlag = b[0]&0x80 == 0x80
	nf.NFlag = b[0]&0x40 == 0x40

	return nf, nil
}

// UnmarshalOSPFv3Flags build Prefix Attr OSPFv3 Flags Object
func UnmarshalOSPFv3Flags(b []byte) (*OSPFv3Flags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal Prefix Attr OSPF Flags")
	}
	nf := &OSPFv3Flags{}

	nf.NFlag = b[0]&0x20 == 0x20
	nf.DNFlag = b[0]&0x10 == 0x10
	nf.PFlag = b[0]&0x08 == 0x08
	nf.LAFlag = b[0]&0x02 == 0x02
	nf.NUFlag = b[0]&0x01 == 0x01

	return nf, nil
}

// UnmarshalUnknownProtoFlags build Prefix Attr Flags Object if protocol is neither ISIS nor OSPF
func UnmarshalUnknownProtoFlags(b []byte) (*UnknownProtoFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal Prefix Attr Flags")
	}
	nf := &UnknownProtoFlags{}
	nf.Flags = b[0]

	return nf, nil
}

// https://datatracker.ietf.org/doc/html/rfc7794#section-2.1
// 0 1 2 3 4 5 6 7...
// +-+-+-+-+-+-+-+-+...
// |X|R|N|          ...
// +-+-+-+-+-+-+-+-+...
// ISISFlags defines a structure of ISIS Prefix Attr flags
type ISISFlags struct {
	XFlag bool `json:"x_flag"`
	RFlag bool `json:"r_flag"`
	NFlag bool `json:"n_flag"`
}

//GetPrefixAttrFlagsByte returns a byte represenation for ISIS flags
func (f *ISISFlags) GetPrefixAttrFlagsByte() byte {
	b := byte(0)
	if f.XFlag {
		b += 0x80
	}
	if f.RFlag {
		b += 0x40
	}
	if f.NFlag {
		b += 0x20
	}

	return b
}

// https://datatracker.ietf.org/doc/html/rfc7684#section-2.1
// OSPFFlags defines a structure of OSPF Prefix Attr flags
type OSPFFlags struct {
	AFlag bool `json:"a_flag"`
	NFlag bool `json:"n_flag"`
}

//GetPrefixAttrFlagsByte returns a byte represenation for OSPF flags
func (f *OSPFFlags) GetPrefixAttrFlagsByte() byte {
	b := byte(0)

	if f.AFlag {
		b += 0x80
	}
	if f.NFlag {
		b += 0x20
	}

	return b
}

//   0  1  2  3  4  5  6  7
// +--+--+--+--+--+--+--+--+
// |  |  | N|DN| P| x|LA|NU|
// +--+--+--+--+--+--+--+--+
// OSPFv3Flags defines a structure of OSPFv3 Prefix Attr flags
type OSPFv3Flags struct {
	NFlag  bool `json:"n_flag"`
	DNFlag bool `json:"dn_flag"`
	PFlag  bool `json:"p_flag"`
	LAFlag bool `json:"la_flag"`
	NUFlag bool `json:"nu_flag"`
}

//GetPrefixAttrFlagsByte returns a byte represenation for OSPF flags
func (f *OSPFv3Flags) GetPrefixAttrFlagsByte() byte {
	b := byte(0)

	if f.NFlag {
		b += 0x20
	}
	if f.DNFlag {
		b += 0x10
	}
	if f.PFlag {
		b += 0x08
	}
	if f.LAFlag {
		b += 0x02
	}
	if f.NUFlag {
		b += 0x01
	}

	return b
}

// UnknownProtoFlags defines a structure of Unknown protocol of Prefix Attr flags
type UnknownProtoFlags struct {
	Flags byte `json:"flags"`
}

//GetPrefixAttrFlagsByte returns a byte represenation for Unknown protocol flags
func (f *UnknownProtoFlags) GetPrefixAttrFlagsByte() byte {
	return f.Flags
}

// RangeTLV defines Range TLV Object per RFC 9085 Section 2.3.5
type RangeTLV struct {
	Flags     RangeTLVFlags      `json:"flags,omitempty"`
	RangeSize uint16             `json:"range_size"`
	PrefixSID []*sr.PrefixSIDTLV `json:"prefix_sid,omitempty"`
}

// RangeTLVFlags interface for protocol-specific flags
type RangeTLVFlags interface {
	GetRangeFlagsByte() byte
}

// ISISRangeFlags for IS-IS protocol (RFC 8667)
type ISISRangeFlags struct {
	FFlag bool `json:"f_flag"` // Address-Family Flag
	MFlag bool `json:"m_flag"` // Mirror Context Flag
	SFlag bool `json:"s_flag"` // Scope Flag
	DFlag bool `json:"d_flag"` // Down Flag
	AFlag bool `json:"a_flag"` // Attached Flag
}

func (f *ISISRangeFlags) GetRangeFlagsByte() byte {
	var b byte
	if f.FFlag {
		b |= 0x80
	}
	if f.MFlag {
		b |= 0x40
	}
	if f.SFlag {
		b |= 0x20
	}
	if f.DFlag {
		b |= 0x10
	}
	if f.AFlag {
		b |= 0x08
	}
	return b
}

// OSPFRangeFlags for OSPF/OSPFv3 (RFC 8665)
type OSPFRangeFlags struct {
	IAFlag bool `json:"ia_flag"` // Inter-Area Flag
}

func (f *OSPFRangeFlags) GetRangeFlagsByte() byte {
	if f.IAFlag {
		return 0x80
	}
	return 0x00
}

// UnknownProtoRangeFlags for unknown protocols
type UnknownProtoRangeFlags struct {
	Flags byte `json:"flags"`
}

func (f *UnknownProtoRangeFlags) GetRangeFlagsByte() byte {
	return f.Flags
}

// UnmarshalRangeTLVFlags parses protocol-specific Range TLV flags
func UnmarshalRangeTLVFlags(b byte, proto base.ProtoID) (RangeTLVFlags, error) {
	switch proto {
	case base.ISISL1, base.ISISL2:
		return &ISISRangeFlags{
			FFlag: b&0x80 == 0x80,
			MFlag: b&0x40 == 0x40,
			SFlag: b&0x20 == 0x20,
			DFlag: b&0x10 == 0x10,
			AFlag: b&0x08 == 0x08,
		}, nil
	case base.OSPFv2, base.OSPFv3:
		return &OSPFRangeFlags{
			IAFlag: b&0x80 == 0x80,
		}, nil
	default:
		return &UnknownProtoRangeFlags{Flags: b}, nil
	}
}

// UnmarshalRangeTLV builds Range TLV Object (RFC 9085 Section 2.3.5)
func UnmarshalRangeTLV(b []byte, proto base.ProtoID) (*RangeTLV, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("Range TLV too short: %d bytes, expected at least 4", len(b))
	}

	rtlv := &RangeTLV{}
	p := 0

	// Parse flags (1 byte)
	flags, err := UnmarshalRangeTLVFlags(b[p], proto)
	if err != nil {
		return nil, err
	}
	rtlv.Flags = flags
	p++

	// Skip reserved byte
	p++

	// Parse Range Size (2 bytes)
	rtlv.RangeSize = binary.BigEndian.Uint16(b[p : p+2])
	p += 2

	// Parse sub-TLVs (remaining bytes)
	if p < len(b) {
		subTLVs, err := base.UnmarshalSubTLV(b[p:])
		if err != nil {
			return nil, err
		}

		// Extract Prefix-SID TLVs (Type 1158)
		rtlv.PrefixSID = make([]*sr.PrefixSIDTLV, 0)
		for _, stlv := range subTLVs {
			if stlv.Type == 1158 {
				psid, err := sr.UnmarshalPrefixSIDTLV(stlv.Value, proto)
				if err != nil {
					return nil, err
				}
				rtlv.PrefixSID = append(rtlv.PrefixSID, psid)
			}
		}
	}

	return rtlv, nil
}

func (ls *NLRI) GetPrefixAttrTLVs(proto base.ProtoID) (*PrefixAttrTLVs, error) {
	pr := &PrefixAttrTLVs{}

	if ps, err := ls.GetLSPrefixSID(proto); err == nil {
		pr.LSPrefixSID = ps
	}
	if r, err := ls.GetLSRangeTLV(proto); err == nil {
		pr.Range = r
	}
	if paf, err := ls.GetLSPrefixAttrFlags(proto); err == nil {
		pr.Flags = paf
	}
	if s, err := ls.GetLSSourceRouterID(); err == nil {
		pr.SourceRouterID = s
	}
	// Do not want to return instantiated but empty object if non of attributes present
	// returning instantiated object if there is at least 1 initialized attribute.
	if len(pr.LSPrefixSID) == 0 && pr.Range == nil && pr.Flags == nil && pr.SourceRouterID == "" {
		return nil, fmt.Errorf("none of prefix attribute tlvs is present")
	}

	return pr, nil
}
