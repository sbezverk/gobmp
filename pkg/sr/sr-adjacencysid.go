package sr

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// AdjacencySIDTLV defines Prefix SID TLV Object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.2.1
type AdjacencySIDTLV struct {
	Flags  AdjacencySIDFlags `json:"flags,omitempty"`
	Weight uint8             `json:"weight"`
	SID    []byte            `json:"sid,omitempty"`
}

// UnmarshalAdjacencySIDTLV builds Adjacency SID TLV Object
func UnmarshalAdjacencySIDTLV(protoID base.ProtoID, b []byte) (*AdjacencySIDTLV, error) {
	glog.V(6).Infof("Adjacency SID Raw: %s", tools.MessageHex(b))
	asid := AdjacencySIDTLV{}
	p := 0
	switch protoID {
	case base.ISISL1:
		fallthrough
	case base.ISISL2:
		asid.Flags = UnmarshalAdjacencySIDISISFlags(b[p])
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		asid.Flags = UnmarshalAdjacencySIDOSPFFlags(b[p])
	}

	p++
	asid.Weight = b[p]
	p++
	// SID length would be Length of b - Flags 1 byte - Weight 1 byte - 2 bytes Reserved
	sl := len(b) - 4
	asid.SID = make([]byte, len(b)-4)
	p += 2
	copy(asid.SID, b[p:p+sl])

	return &asid, nil
}

// AdjacencySIDFlags used for "duck typing", PrefixSID Flags are different for different protocols,
//  this interface will allow to integrate it in a common Adjacency SID structure.
type AdjacencySIDFlags interface {
	MarshalJSON() ([]byte, error)
}

// AdjacencySIDISISFlags defines methods to check AdjacencySID ISIS flags
type AdjacencySIDISISFlags interface {
	IsF() bool
	IsB() bool
	IsV() bool
	IsL() bool
	IsS() bool
	IsP() bool
}

var _ AdjacencySIDISISFlags = &adjISISFlags{}

// 0 1 2 3 4 5 6 7
//+-+-+-+-+-+-+-+-+
//|F|B|V|L|S|P|   |
//+-+-+-+-+-+-+-+-+

type adjISISFlags struct {
	F bool `json:"f_flag"`
	B bool `json:"b_flag"`
	V bool `json:"v_flag"`
	L bool `json:"l_flag"`
	S bool `json:"s_flag"`
	P bool `json:"p_flag"`
}

func (f *adjISISFlags) IsF() bool {
	return f.F
}

func (f *adjISISFlags) IsB() bool {
	return f.B
}

func (f *adjISISFlags) IsV() bool {
	return f.V
}

func (f *adjISISFlags) IsL() bool {
	return f.L
}

func (f *adjISISFlags) IsS() bool {
	return f.S
}

func (f *adjISISFlags) IsP() bool {
	return f.P
}

func (f *adjISISFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		F bool `json:"f_flag"`
		B bool `json:"b_flag"`
		V bool `json:"v_flag"`
		L bool `json:"l_flag"`
		S bool `json:"s_flag"`
		P bool `json:"p_flag"`
	}{
		F: f.F,
		B: f.B,
		V: f.V,
		L: f.L,
		S: f.S,
		P: f.P,
	})
}

// UnmarshalAdjacencySIDISISFlags instantiates Adjacency SID Flags interface from the byte
func UnmarshalAdjacencySIDISISFlags(b byte) AdjacencySIDFlags {
	f := &adjISISFlags{}
	f.F = b&0x80 == 0x80
	f.B = b&0x40 == 0x40
	f.V = b&0x20 == 0x20
	f.L = b&0x10 == 0x10
	f.S = b&0x8 == 0x8
	f.P = b&0x4 == 0x4

	return f
}

func buildAdjISISFlags(b map[string]json.RawMessage) (AdjacencySIDFlags, error) {
	f := &adjISISFlags{}
	f.F = false
	if v, ok := b["f_flag"]; ok {
		if err := json.Unmarshal(v, &f.F); err != nil {
			return nil, err
		}
	}
	f.B = false
	if v, ok := b["b_flag"]; ok {
		if err := json.Unmarshal(v, &f.B); err != nil {
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
	f.S = false
	if v, ok := b["s_flag"]; ok {
		if err := json.Unmarshal(v, &f.S); err != nil {
			return nil, err
		}
	}
	f.P = false
	if v, ok := b["p_flag"]; ok {
		if err := json.Unmarshal(v, &f.P); err != nil {
			return nil, err
		}
	}

	return f, nil
}

// UnmarshalAdjacencySIDOSPFFlags instantiates Adjacency SID Flags interface from the byte
func UnmarshalAdjacencySIDOSPFFlags(b byte) AdjacencySIDFlags {
	f := &adjISISFlags{}
	f.F = b&0x80 == 0x80
	f.B = b&0x40 == 0x40
	f.V = b&0x20 == 0x20
	f.L = b&0x10 == 0x10
	f.S = b&0x8 == 0x8
	f.P = b&0x4 == 0x4

	return f
}
