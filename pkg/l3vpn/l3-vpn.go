package l3vpn

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalL3VPNNLRI instantiates a L3 VPN NLRI object
func UnmarshalL3VPNNLRI(b []byte, pathID bool, srv6 ...bool) (*base.MPNLRI, error) {
	srv6Flag := false
	if len(srv6) == 1 {
		srv6Flag = srv6[0]
	}
	if glog.V(6) {
		glog.Infof("L3VPN NLRI Raw: %s path ID flag: %t srv6 flag: %t ", tools.MessageHex(b), pathID, srv6Flag)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	mpnlri := base.MPNLRI{
		NLRI: make([]base.Route, 0),
	}
	var err error = nil
	for p := 0; p < len(b); {
		up := base.Route{
			Label: make([]*base.Label, 0),
		}
		if pathID {
			if p+4 > len(b) {
				err = fmt.Errorf("not enough bytes to reconstruct l3vpn nlri")
				goto error_handle
			}
			up.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}
		up.Length = b[p]
		if up.Length <= 0 {
			err = fmt.Errorf("not enough bytes to reconstruct l3vpn nlri")
			goto error_handle
		}
		if p+1 > len(b) {
			err = fmt.Errorf("not enough bytes to reconstruct l3vpn nlri")
			goto error_handle
		}
		p++
		// Next 3 bytes are a part of Compatibility field 0x800000
		// then it is MP_UNREACH_NLRI and no Label information is present
		compatibilityField := 0
		if p+3 > len(b) {
			err = fmt.Errorf("not enough bytes to reconstruct l3vpn nlri")
			goto error_handle
		}
		if bytes.Equal([]byte{0x80, 0x00, 0x00}, b[p:p+3]) {
			up.Label = nil
			compatibilityField = 3
			p += 3
		} else {
			// Otherwise getting labels
			up.Label = make([]*base.Label, 0)
			bos := false
			for !bos && p < len(b) {
				if p+3 > len(b) {
					err = fmt.Errorf("not enough bytes to reconstruct l3vpn nlri")
					goto error_handle
				}
				l, e := base.MakeLabel(b[p:p+3], srv6Flag)
				if e != nil {
					err = e
					goto error_handle
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
		if p+8 > len(b) {
			err = fmt.Errorf("not enough bytes to reconstruct l3vpn nlri")
			goto error_handle
		}
		rd, e := base.MakeRD(b[p : p+8])
		if e != nil {
			err = e
			goto error_handle
		}
		p += 8
		up.RD = rd
		// Adjusting prefix length to remove bits used by labels each label takes 3 bytes, or 3 bytes
		// of Compatibility field
		l := int(up.Length/8) - (len(up.Label) * 3) - compatibilityField - 8
		if l < 0 {
			err = fmt.Errorf("not enough bytes to reconstruct l3vpn nlri")
			goto error_handle
		}
		if up.Length%8 != 0 {
			l++
		}
		if p+l > len(b) {
			err = fmt.Errorf("not enough bytes to reconstruct l3vpn nlri")
			goto error_handle
		}
		up.Prefix = make([]byte, l)
		copy(up.Prefix, b[p:p+l])
		p += l
		up.Length = uint8(l * 8)
		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

error_handle:
	if err != nil {
		// In some cases, Error could be triggered by use of incorrect value of PathID flag, as Add Path capability
		// might be advertised and received, but BGP Update would not have PathID set due to some other conditions,
		// example when bgp speakers are in different AS. In error handle, attempting to Unmarshal again with reversed
		// value of PathID flag.
		if mp, e := UnmarshalL3VPNNLRI(b, !pathID, srv6Flag); e == nil {
			return mp, nil
		}
		glog.Errorf("failed to reconstruct l3vpn nlri from slice %s with error: %+v", tools.MessageHex(b), err)

		return nil, err
	}

	return &mpnlri, nil
}
