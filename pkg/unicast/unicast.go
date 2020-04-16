package unicast

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// MPUnicastPrefix defines a single NLRI entry
type MPUnicastPrefix struct {
	AFI    uint16
	SAFI   uint8
	Count  uint8
	Length uint8
	Prefix []byte
}

// MPUnicastNLRI defines a collection of MP Unicast Prefixes recieved in MP_BGP_REACH_NLRI
type MPUnicastNLRI struct {
	NLRI []MPUnicastPrefix
}

// UnmarshalUnicastNLRI builds MP NLRI object from the slice of bytes
func UnmarshalUnicastNLRI(b []byte) (*MPUnicastNLRI, error) {
	glog.V(5).Infof("MP Unicast NLRI Raw: %s", tools.MessageHex(b))
	mpnlri := MPUnicastNLRI{
		NLRI: make([]MPUnicastPrefix, 0),
	}
	for p := 0; p < len(b); {
		up := MPUnicastPrefix{}
		up.AFI = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		up.SAFI = b[p]
		p++
		up.Count = b[p]
		p++
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

// MPLUPrefix defines a single NLRI entry
type MPLUPrefix struct {
	AFI    uint16
	SAFI   uint8
	Count  uint8
	Length uint8
	Label  []*base.Label
	Prefix []byte
}

// MPLUNLRI defines a collection of MP Unicast Prefixes recieved in MP_BGP_REACH_NLRI
type MPLUNLRI struct {
	NLRI []MPLUPrefix
}

// UnmarshalLUNLRI builds MP NLRI object from the slice of bytes
func UnmarshalLUNLRI(b []byte) (*MPLUNLRI, error) {
	glog.V(5).Infof("MP Label Unicast NLRI Raw: %s", tools.MessageHex(b))
	mpnlri := MPLUNLRI{
		NLRI: make([]MPLUPrefix, 0),
	}
	for p := 0; p < len(b); {
		up := MPLUPrefix{
			Label: make([]*base.Label, 0),
		}
		up.AFI = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		up.SAFI = b[p]
		p++
		up.Count = b[p]
		p++
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
		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

	return &mpnlri, nil
}
