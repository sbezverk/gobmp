package bgpls

import (
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PrefixAttrTLVs defines a struvture for Prefix Attributes as defined in the following RFC proposal:
// https://datatracker.ietf.org/doc/html/draft-ietf-idr-bgp-ls-segment-routing-ext-17#section-2.3
type PrefixAttrTLVs struct {
	LSPrefixSID []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
	// TODO (sbezverk) Add "Range" TLV 1159
	Flags          PrefixAttrFlags `json:"prefix_attr_flags"`
	SourceRouterID string          `json:"source_router_id,omitempty"`
	// TODO (sbezverk) Add "Source OSPF Router-ID" TLV 1174
}

// PrefixAttrFlags defines Prefix Attribute Flags interface
type PrefixAttrFlags interface {
	GetPrefixAttrFlagsByte() byte
}

func (p *PrefixAttrTLVs) MarshalJSON() ([]byte, error) {
	switch p.Flags.(type) {
	case *ISISFlags:
		f := p.Flags.(*ISISFlags)
		return json.Marshal(struct {
			LSPrefixSID    []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
			Flags          *ISISFlags         `json:"flags,omitempty"`
			SourceRouterID string             `json:"source_router_id,omitempty"`
		}{
			Flags: f,
		})
	case *OSPFFlags:
		f := p.Flags.(*OSPFFlags)
		return json.Marshal(struct {
			LSPrefixSID    []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
			Flags          *OSPFFlags         `json:"flags,omitempty"`
			SourceRouterID string             `json:"source_router_id,omitempty"`
		}{
			Flags: f,
		})
	default:
		f := p.Flags.(*UnknownProtoFlags)
		return json.Marshal(struct {
			LSPrefixSID    []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
			Flags          *UnknownProtoFlags `json:"flags,omitempty"`
			SourceRouterID string             `json:"source_router_id,omitempty"`
		}{
			Flags: f,
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
	// LSPrefixSID    []*sr.PrefixSIDTLV `json:"ls_prefix_sid,omitempty"`
	if v, ok := objVal["ls_prefix_sid"]; ok {
		if err := json.Unmarshal(v, &result.LSPrefixSID); err != nil {
			return err
		}
	}
	// SourceRouterID string             `json:"source_router_id,omitempty"`
	if v, ok := objVal["prefix_sid"]; ok {
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
		fallthrough
	case base.OSPFv3:
		return UnmarshalOSPFFlags(b[p : p+1])
	default:
		return UnmarshalUnknownProtoFlags(b[p : p+1])
	}
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

//GetPrefixAttrFlagsByte returns a byte represenation for ISIS flags
func (f *ISISFlags) GetPrefixAttrFlagsByte() byte {
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

//GetPrefixAttrFlagsByte returns a byte represenation for OSPF flags
func (f *OSPFFlags) GetPrefixAttrFlagsByte() byte {
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

//GetPrefixAttrFlagsByte returns a byte represenation for Unknown protocol flags
func (f *UnknownProtoFlags) GetPrefixAttrFlagsByte() byte {
	return f.Flags
}

func (ls *NLRI) GetPrefixAttrTLVs(proto base.ProtoID) (*PrefixAttrTLVs, error) {
	pr := &PrefixAttrTLVs{}
	if ps, err := ls.GetLSPrefixSID(proto); err == nil {
		pr.LSPrefixSID = ps
	}
	if paf, err := ls.GetLSPrefixAttrFlags(proto); err == nil {
		pr.Flags = paf
	}
	if s, err := ls.GetLSSourceRouterID(); err == nil {
		pr.SourceRouterID = s
	}

	return pr, nil
}
