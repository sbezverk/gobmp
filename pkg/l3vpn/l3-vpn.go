package l3vpn

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// NLRI defines L3 VPN NLRI object
type NLRI struct {
	Length uint8
	Labels []*base.Label
	RD     *base.RD
	Prefix []byte
}

// GetL3VPNPrefix returns l3 vpn prefix as a full size slice, not just significant bits,
// to be suitable for converting into a string with net.IP
func (n *NLRI) GetL3VPNPrefix() []byte {
	if len(n.Prefix) == 4 {
		return n.Prefix
	}
	p := make([]byte, 4)
	copy(p, n.Prefix)

	return p
}

// UnmarshalL3VPNNLRI instantiates a L3 VPN NLRI object
func UnmarshalL3VPNNLRI(b []byte) (*NLRI, error) {
	glog.V(6).Infof("L3VPN NLRI Raw: %s", tools.MessageHex(b))
	n := NLRI{}
	p := 0
	// Getting length of NLRI in bytes
	n.Length = uint8(b[p] / 8)
	p++
	n.Labels = make([]*base.Label, 0)
	// subtract 12 from the length as label stack follows by RD 8 bytes and prefix 4 bytes
	bos := false
	for !bos {
		l, err := base.MakeLabel(b[p : p+3])
		if err != nil {
			return nil, err
		}
		n.Labels = append(n.Labels, l)
		p += 3
		bos = l.BoS
	}
	rd, err := base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, err
	}
	p += 8
	n.RD = rd
	l := len(b) - p
	n.Prefix = make([]byte, l)
	copy(n.Prefix, b[p:])

	return &n, nil
}
