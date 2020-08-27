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
		psid.Flags = unmarshalISISFlags(b[p])
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		psid.Flags = unmarshalOSPFFlags(b[p])
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

// PrefixSIDFlags used for "duck typing", PrefixSID Flags are different for different protocols,
//  this interface will allow to integrate it in a common PrefixSID structure.
type PrefixSIDFlags interface {
	MarshalJSON() ([]byte, error)
}

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

func unmarshalISISFlags(b byte) PrefixSIDFlags {
	f := &isisFlags{}
	f.R = b&0x80 == 0x80
	f.N = b&0x40 == 0x40
	f.P = b&0x20 == 0x20
	f.E = b&0x10 == 0x10
	f.V = b&0x8 == 0x8
	f.L = b&0x4 == 0x4

	return f
}

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

func unmarshalOSPFFlags(b byte) PrefixSIDFlags {
	f := &ospfFlags{}
	f.NP = b&0x40 == 0x40
	f.M = b&0x20 == 0x20
	f.E = b&0x10 == 0x10
	f.V = b&0x8 == 0x8
	f.L = b&0x4 == 0x4

	return f
}
