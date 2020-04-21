// Serge Krier April 2020

package bgp

import (
	"encoding/binary"
	"fmt"
)

// LgCommunity defines BGP Large Commuity https://tools.ietf.org/html/rfc8092
type LgCommunity struct {
	GlobalAdmin uint32
	LocalData1  uint32
	LocalData2  uint32
}

func makeLgCommunity(b []byte) (*LgCommunity, error) {
	lg := LgCommunity{}
	if len(b) != 12 {
		return nil, fmt.Errorf("invalid length expected 12 got %d", len(b))
	}
	lg.GlobalAdmin = binary.BigEndian.Uint32(b[:4])
	lg.LocalData1 = binary.BigEndian.Uint32(b[4:8])
	lg.LocalData2 = binary.BigEndian.Uint32(b[8:12])

	return &lg, nil
}

func (lg *LgCommunity) String() string {
	return fmt.Sprintf("%d:%d:%d", lg.GlobalAdmin, lg.LocalData1, lg.LocalData2)
}

// UnmarshalBGPLgCommunity builds a slice of Large Communities
func UnmarshalBGPLgCommunity(b []byte) ([]LgCommunity, error) {
	lgs := make([]LgCommunity, 0)
	for p := 0; p < len(b); {
		lg, err := makeLgCommunity(b[p : p+12])
		if err != nil {
			return nil, err
		}
		p += 12
		lgs = append(lgs, *lg)
	}

	return lgs, nil
}
