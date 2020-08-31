package sr

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Flags carries PrefixSID flag bits
//  0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |R|N|P|E|V|L|   |
// +-+-+-+-+-+-+-+-+
// type Flags struct {
// 	R bool `json:"r_flag"`
// 	N bool `json:"n_flag"`
// 	P bool `json:"p_flag"`
// 	E bool `json:"e_flag"`
// 	V bool `json:"v_flag"`
// 	L bool `json:"l_flag"`
// }

// PrefixSIDTLV defines Prefix SID TLV Object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.3.1
type PrefixSIDTLV struct {
	Flags     PrefixSIDFlags `json:"flags,omitempty"`
	Algorithm uint8          `json:"algo"`
	SID       []byte         `json:"prefix_sid,omitempty"`
}

// UnmarshalPrefixSIDTLV builds Prefix SID TLV Object
func UnmarshalPrefixSIDTLV(protoID base.ProtoID, b []byte) (*PrefixSIDTLV, error) {
	glog.V(6).Infof("Prefix SID TLV Raw: %s", tools.MessageHex(b))
	psid := PrefixSIDTLV{}
	p := 0
	switch protoID {
	case base.ISISL1:
		fallthrough
	case base.ISISL2:
		psid.Flags = UnmarshalPrefixSIDISISFlags(b[p])
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		psid.Flags = UnmarshalPrefixSIDOSPFFlags(b[p])
	}
	p++
	psid.Algorithm = b[p]
	p++
	// SID length would be Length of b - Flags 1 byte - Algorithm 1 byte - 2 bytes Reserved
	sl := len(b) - 4
	psid.SID = make([]byte, len(b)-4)
	p += 2
	copy(psid.SID, b[p:p+sl])

	return &psid, nil
}

// BuildPrefixSID builds Prefix SID TLV Object from json map[string]json.RawMessage
func BuildPrefixSID(protoID base.ProtoID, b map[string]json.RawMessage) (*PrefixSIDTLV, error) {
	psid := PrefixSIDTLV{}
	if v, ok := b["flags"]; ok {
		var fo map[string]json.RawMessage
		if err := json.Unmarshal(v, &fo); err != nil {
			return nil, err
		}
		switch protoID {
		case base.ISISL1:
			fallthrough
		case base.ISISL2:
			f, err := buildISISFlags(fo)
			if err != nil {
				return nil, err
			}
			psid.Flags = f
		case base.OSPFv2:
			fallthrough
		case base.OSPFv3:
			f, err := buildOSPFFlags(fo)
			if err != nil {
				return nil, err
			}
			psid.Flags = f
		}
	}
	if v, ok := b["algo"]; ok {
		if err := json.Unmarshal(v, &psid.Algorithm); err != nil {
			return nil, err
		}
	}
	if v, ok := b["prefix_sid"]; ok {
		if err := json.Unmarshal(v, &psid.SID); err != nil {
			return nil, err
		}
	}

	return &psid, nil
}

// PrefixSIDFlags used for "duck typing", PrefixSID Flags are different for different protocols,
//  this interface will allow to integrate it in a common PrefixSID structure.
type PrefixSIDFlags interface {
	MarshalJSON() ([]byte, error)
}

// PrefixSIDISISFlags defines methods to check PrefixSID ISIS flags
type PrefixSIDISISFlags interface {
	IsR() bool
	IsN() bool
	IsP() bool
	IsE() bool
	IsV() bool
	IsL() bool
}

var _ PrefixSIDISISFlags = &isisFlags{}

// Flags carries PrefixSID flag bits
//  0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |R|N|P|E|V|L|   |
// +-+-+-+-+-+-+-+-+
type isisFlags struct {
	R bool `json:"r_flag"`
	N bool `json:"n_flag"`
	P bool `json:"p_flag"`
	E bool `json:"e_flag"`
	V bool `json:"v_flag"`
	L bool `json:"l_flag"`
}

func (f *isisFlags) IsR() bool {
	return f.R
}

func (f *isisFlags) IsN() bool {
	return f.N
}

func (f *isisFlags) IsP() bool {
	return f.P
}

func (f *isisFlags) IsE() bool {
	return f.E
}

func (f *isisFlags) IsV() bool {
	return f.V
}

func (f *isisFlags) IsL() bool {
	return f.L
}

func (f *isisFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		R bool `json:"r_flag"`
		N bool `json:"n_flag"`
		P bool `json:"p_flag"`
		E bool `json:"e_flag"`
		V bool `json:"v_flag"`
		L bool `json:"l_flag"`
	}{
		R: f.R,
		N: f.N,
		P: f.P,
		E: f.E,
		V: f.V,
		L: f.L,
	})
}

// UnmarshalPrefixSIDISISFlags instantiates PrefixSIDFlags interface from the byte
func UnmarshalPrefixSIDISISFlags(b byte) PrefixSIDFlags {
	f := &isisFlags{}
	f.R = b&0x80 == 0x80
	f.N = b&0x40 == 0x40
	f.P = b&0x20 == 0x20
	f.E = b&0x10 == 0x10
	f.V = b&0x8 == 0x8
	f.L = b&0x4 == 0x4

	return f
}

func buildISISFlags(b map[string]json.RawMessage) (PrefixSIDFlags, error) {
	f := &isisFlags{}
	f.R = false
	if v, ok := b["r_flag"]; ok {
		if err := json.Unmarshal(v, &f.R); err != nil {
			return nil, err
		}
	}
	f.N = false
	if v, ok := b["n_flag"]; ok {
		if err := json.Unmarshal(v, &f.N); err != nil {
			return nil, err
		}
	}
	f.P = false
	if v, ok := b["p_flag"]; ok {
		if err := json.Unmarshal(v, &f.P); err != nil {
			return nil, err
		}
	}
	f.E = false
	if v, ok := b["e_flag"]; ok {
		if err := json.Unmarshal(v, &f.E); err != nil {
			return nil, err
		}
	}
	f.V = false
	if v, ok := b["v_flag"]; ok {
		if err := json.Unmarshal(v, &f.V); err != nil {
			return nil, err
		}
	}
	f.L = false
	if v, ok := b["l_flag"]; ok {
		if err := json.Unmarshal(v, &f.L); err != nil {
			return nil, err
		}
	}

	return f, nil
}

// PrefixSIDISISFlags defines methods to check PrefixSID ISIS flags
type PrefixSIDOSPFFlags interface {
	IsNP() bool
	IsM() bool
	IsE() bool
	IsV() bool
	IsL() bool
}

var _ PrefixSIDOSPFFlags = &ospfFlags{}

//   0  1  2  3  4  5  6  7
// +--+--+--+--+--+--+--+--+
// |  |NP|M |E |V |L |  |  |
// +--+--+--+--+--+--+--+--+
type ospfFlags struct {
	NP bool `json:"np_flag"`
	M  bool `json:"m_flag"`
	E  bool `json:"e_flag"`
	V  bool `json:"v_flag"`
	L  bool `json:"l_flag"`
}

func (f *ospfFlags) IsNP() bool {
	return f.NP
}

func (f *ospfFlags) IsM() bool {
	return f.M
}

func (f *ospfFlags) IsE() bool {
	return f.E
}

func (f *ospfFlags) IsV() bool {
	return f.V
}

func (f *ospfFlags) IsL() bool {
	return f.L
}

func (f *ospfFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		NP bool `json:"np_flag"`
		M  bool `json:"m_flag"`
		E  bool `json:"e_flag"`
		V  bool `json:"v_flag"`
		L  bool `json:"l_flag"`
	}{
		NP: f.NP,
		M:  f.M,
		E:  f.E,
		V:  f.V,
		L:  f.L,
	})
}

// UnmarshalPrefixSIDOSPFFlags instantiates PrefixSIDFlags interface from the byte
func UnmarshalPrefixSIDOSPFFlags(b byte) PrefixSIDFlags {
	f := &ospfFlags{}
	f.NP = b&0x40 == 0x40
	f.M = b&0x20 == 0x20
	f.E = b&0x10 == 0x10
	f.V = b&0x8 == 0x8
	f.L = b&0x4 == 0x4

	return f
}

func buildOSPFFlags(b map[string]json.RawMessage) (PrefixSIDFlags, error) {
	f := &ospfFlags{}

	f.NP = false
	if v, ok := b["np_flag"]; ok {
		if err := json.Unmarshal(v, &f.NP); err != nil {
			return nil, err
		}
	}
	f.M = false
	if v, ok := b["m_flag"]; ok {
		if err := json.Unmarshal(v, &f.M); err != nil {
			return nil, err
		}
	}
	f.E = false
	if v, ok := b["e_flag"]; ok {
		if err := json.Unmarshal(v, &f.E); err != nil {
			return nil, err
		}
	}
	f.V = false
	if v, ok := b["v_flag"]; ok {
		if err := json.Unmarshal(v, &f.V); err != nil {
			return nil, err
		}
	}
	f.L = false
	if v, ok := b["l_flag"]; ok {
		if err := json.Unmarshal(v, &f.L); err != nil {
			return nil, err
		}
	}

	return f, nil
}
