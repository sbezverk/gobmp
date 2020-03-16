package srv6

import (
	"github.com/sbezverk/gobmp/pkg/internal"
)

// SubTLV defines SRv6 Sub TLV object
// No RFC yet
type SubTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func (stlv *SubTLV) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += internal.AddLevel(l)

	return s
}

// UnmarshalSRv6SubTLV builds a collection of SRv6 Sub TLV
func UnmarshalSRv6SubTLV(b []byte) ([]SubTLV, error) {
	stlvs := make([]SubTLV, 0)

	return stlvs, nil
}
