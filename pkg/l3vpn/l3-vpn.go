package l3vpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// NLRI defines L3 VPN NLRI object
type NLRI struct {
	Length uint8
	Labels []*base.Label
	RD     *base.RD
	Prefix []byte
}

// UnmarshalL3VPNNLRI instantiates a L3 VPN NLRI object
func UnmarshalL3VPNNLRI(b []byte) (*NLRI, error) {
	n := NLRI{}
	p := 0
	// Getting length of NLRI in bytes
	n.Length = uint8(b[p] / 8)
	p++
	n.Labels = make([]*base.Label, 0)
	// subtract 12 for the length as label stack follows by RD 8 bytes and prefix 4 bytes
	for p < len(b)-12 {
		l, err := base.MakeLabel(b[p : p+3])
		if err != nil {
			return nil, err
		}
		n.Labels = append(n.Labels, l)
		p += 3
	}
	if p+12 != len(b) {
		// Something went wrong do not have enough bytes to decode RD and Prefix
		// bailing out before making panic.
		return nil, fmt.Errorf("failed to construct l3vpn NLRI, invalid data detected")
	}
	rd, err := base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, err
	}
	p += 8
	n.RD = rd
	n.Prefix = make([]byte, 4)
	copy(n.Prefix, b[p:])

	return &n, nil
}
