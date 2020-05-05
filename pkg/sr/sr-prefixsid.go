package sr

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Flags carries PrefixSID flag bits
//  0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |R|N|P|E|V|L|   |
// +-+-+-+-+-+-+-+-+
type Flags struct {
	R bool `json:"r_flag"`
	N bool `json:"n_flag"`
	P bool `json:"p_flag"`
	E bool `json:"e_flag"`
	V bool `json:"v_flag"`
	L bool `json:"l_flag"`
}

// PrefixSIDTLV defines Prefix SID TLV Object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.3.1
type PrefixSIDTLV struct {
	Flags     *Flags `json:"flags,omitempty"`
	Algorithm uint8  `json:"algo"`
	SID       []byte `json:"prefix_sid,omitempty"`
}

// UnmarshalPrefixSIDTLV builds Prefix SID TLV Object
func UnmarshalPrefixSIDTLV(b []byte) (*PrefixSIDTLV, error) {
	glog.V(6).Infof("Prefix SID TLV Raw: %s", tools.MessageHex(b))
	psid := PrefixSIDTLV{
		Flags: &Flags{},
	}
	p := 0
	psid.Flags.R = b[p]&0x80 == 0x80
	psid.Flags.N = b[p]&0x40 == 0x40
	psid.Flags.P = b[p]&0x20 == 0x20
	psid.Flags.E = b[p]&0x10 == 0x10
	psid.Flags.V = b[p]&0x8 == 0x8
	psid.Flags.L = b[p]&0x4 == 0x4
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
