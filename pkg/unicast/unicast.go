package unicast

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalUnicastNLRI builds MP NLRI object from the slice of bytes
func UnmarshalUnicastNLRI(b []byte, pathID bool) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Unicast NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	mpnlri := base.MPNLRI{}
	r, err := base.UnmarshalRoutes(b, pathID)
	if err != nil {
		return nil, err
	}
	mpnlri.NLRI = r

	return &mpnlri, nil
}

// UnmarshalLUNLRI builds MP NLRI object from the slice of bytes
func UnmarshalLUNLRI(b []byte, pathID bool) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Label Unicast NLRI Raw: %s path id flag: %t", tools.MessageHex(b), pathID)
	}
	mpnlri := base.MPNLRI{
		NLRI: make([]base.Route, 0),
	}
	for p := 0; p < len(b); {
		up := base.Route{
			Label: make([]*base.Label, 0),
		}
		if pathID {
			if p+4 > len(b) {
				if u, err := UnmarshalLUNLRI(b, !pathID); err == nil {
					return u, nil
				}
				return nil, fmt.Errorf("malformed slice")
			}
			up.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}
		if p+1 > len(b) {
			if u, err := UnmarshalLUNLRI(b, !pathID); err == nil {
				return u, nil
			}
			return nil, fmt.Errorf("malformed slice")
		}
		up.Length = b[p]
		p++
		// Next 3 bytes are a part of Compatibility field 0x800000
		// then it is MP_UNREACH_NLRI and no Label information is present
		compatibilityField := 0
		if p+3 > len(b) {
			if u, err := UnmarshalLUNLRI(b, !pathID); err == nil {
				return u, nil
			}
			return nil, fmt.Errorf("malformed slice")
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
				l, err := base.MakeLabel(b[p : p+3])
				if err != nil {
					return nil, err
				}
				up.Label = append(up.Label, l)
				p += 3
				bos = l.BoS
			}
		}
		// Adjusting prefix length to remove bits used by labels each label takes 3 bytes, or 3 bytes
		// of Compatibility field
		l := int(up.Length/8) - (len(up.Label) * 3) - compatibilityField
		if l < 0 {
			if u, err := UnmarshalLUNLRI(b, !pathID); err == nil {
				return u, nil
			}
			return nil, fmt.Errorf("malformed slice")
		}
		if up.Length%8 != 0 {
			l++
		}
		if p+l > len(b) {
			if u, err := UnmarshalLUNLRI(b, !pathID); err == nil {
				return u, nil
			}
			return nil, fmt.Errorf("malformed slice")
		}
		up.Prefix = make([]byte, l)
		copy(up.Prefix, b[p:p+int(l)])
		p += int(l)
		up.Length = uint8(l * 8)
		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

	return &mpnlri, nil
}
