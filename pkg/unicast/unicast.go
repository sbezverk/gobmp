package unicast

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// MPUnicastPrefix defines a single NLRI entry
type MPUnicastPrefix struct {
	AFI    uint16
	SAFI   uint8
	Count  uint8
	Label  []*base.Label
	Length uint8
	Prefix []byte
}

// MPUnicastNLRI defines a collection of MP Unicast Prefixes recieved in MP_BGP_REACH_NLRI
type MPUnicastNLRI struct {
	NLRI []MPUnicastPrefix
}

// UnmarshalUnicastNLRI builds MP NLRI object from the slice of bytes
func UnmarshalUnicastNLRI(b []byte) (*MPUnicastNLRI, error) {
	glog.V(6).Infof("MP Unicast NLRI Raw: %s", tools.MessageHex(b))
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	mpnlri := MPUnicastNLRI{
		NLRI: make([]MPUnicastPrefix, 0),
	}
	for p := 0; p < len(b); {
		up := MPUnicastPrefix{}
		// When default prefix is sent, actual NLRI is 1 byte with value of 0x0
		if b[p] == 0x0 && len(b) != 1 {
			up.AFI = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			up.SAFI = b[p]
			p++
			up.Count = b[p]
			p++
		}
		up.Length = b[p]
		p++
		l := int(up.Length / 8)
		if up.Length%8 != 0 {
			l++
		}
		up.Prefix = make([]byte, l)
		copy(up.Prefix, b[p:p+l])
		p += l
		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

	return &mpnlri, nil
}

// UnmarshalLUNLRI builds MP NLRI object from the slice of bytes
func UnmarshalLUNLRI(b []byte) (*MPUnicastNLRI, error) {
	glog.V(6).Infof("MP Label Unicast NLRI Raw: %s", tools.MessageHex(b))
	mpnlri := MPUnicastNLRI{
		NLRI: make([]MPUnicastPrefix, 0),
	}
	for p := 0; p < len(b); {
		up := MPUnicastPrefix{
			Label: make([]*base.Label, 0),
		}
		if b[p] == 0x0 {
			up.AFI = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
			up.SAFI = b[p]
			p++
			up.Count = b[p]
			p++
		}
		up.Length = b[p]
		p++
		bos := false
		for !bos && p < len(b) {
			label, err := base.MakeLabel(b[p : p+3])
			if err != nil {
				return nil, err
			}
			up.Label = append(up.Label, label)
			bos = label.BoS
			p += 3
		}
		l := int(up.Length/8) - (len(up.Label) * 3)
		if up.Length%8 != 0 {
			l++
		}
		up.Prefix = make([]byte, l)
		copy(up.Prefix, b[p:p+l])
		p += l
		// Adjusting prefix length to remove bits used by labels each label takes 3 bytes or 24 bits
		up.Length -= uint8(len(up.Label) * 24)
		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

	return &mpnlri, nil
}
