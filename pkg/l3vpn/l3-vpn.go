package l3vpn

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// UnmarshalL3VPNNLRI instantiates a L3 VPN NLRI object
func UnmarshalL3VPNNLRI(b []byte, srv6 ...bool) (*base.MPNLRI, error) {
	glog.V(6).Infof("L3VPN NLRI Raw: %s", tools.MessageHex(b))
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	srv6Flag := false
	if len(srv6) == 1 {
		srv6Flag = srv6[0]
	}
	mpnlri := base.MPNLRI{
		NLRI: make([]base.Route, 0),
	}
	for p := 0; p < len(b); {
		up := base.Route{
			Label: make([]*base.Label, 0),
		}
		if b[p] == 0x0 && len(b) > 4 {
			up.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}
		up.Length = b[p]
		p++
		// Next 3 bytes are a part of Compatibility field 0x800000
		// then it is MP_UNREACH_NLRI and no Label information is present
		compatibilityField := 0
		if bytes.Equal([]byte{0x80, 0x00, 0x00}, b[p:p+3]) {
			up.Label = nil
			compatibilityField = 3
			p += 3
		} else {
			// Otherwise getting labels
			up.Label = make([]*base.Label, 0)
			bos := false
			for !bos && p < len(b) {
				l, err := base.MakeLabel(b[p : p+3])
				if err != nil {
					return nil, err
				}
				up.Label = append(up.Label, l)
				p += 3
				bos = l.BoS
				if srv6Flag {
					// When srv6Flag is set, it means 3 bytes of label is not really a label
					// but a part of Prefix SID, as such, BoS does not exists.
					bos = true
				}
			}
		}
		rd, err := base.MakeRD(b[p : p+8])
		if err != nil {
			return nil, err
		}
		p += 8
		up.RD = rd
		// Adjusting prefix length to remove bits used by labels each label takes 3 bytes, or 3 bytes
		// of Compatibility field
		l := int(up.Length/8) - (len(up.Label) * 3) - compatibilityField - 8
		if up.Length%8 != 0 {
			l++
		}
		up.Prefix = make([]byte, l)
		copy(up.Prefix, b[p:p+l])
		p += l
		up.Length = uint8(l * 8)
		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

	return &mpnlri, nil
}
