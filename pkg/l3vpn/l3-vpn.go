package l3vpn

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// NLRI defines L3 VPN NLRI object
type NLRI struct {
	PathID uint32
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
	glog.V(5).Infof("L3VPN NLRI Raw: %s", tools.MessageHex(b))
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	n := NLRI{}
	p := 0
	if b[p] == 0 {
		// NLRI carries Path ID
		n.PathID = binary.BigEndian.Uint32(b[p : p+4])
		p += 4
	}
	// Getting length of NLRI in bytes
	n.Length = uint8(b[p] / 8)
	p++
	// Next 3 bytes are a part of Compatibility field 0x800000
	// then it is MP_UNREACH_NLRI and no Label information is present
	if bytes.Compare([]byte{0x80, 0x00, 0x00}, b[p:p+3]) == 0 {
		n.Labels = nil
		p += 3
	} else {
		// Otherwise getting labels
		n.Labels = make([]*base.Label, 0)
		bos := false
		for !bos && p < len(b) {
			l, err := base.MakeLabel(b[p : p+3])
			if err != nil {
				return nil, err
			}
			n.Labels = append(n.Labels, l)
			p += 3
			bos = l.BoS
		}
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
