package bgp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// MPUnReachNLRI defines an MP UnReach NLRI object
type MPUnReachNLRI struct {
	AddressFamilyID    uint16
	SubAddressFamilyID uint8
	WithdrawnRoutes    []Route
}

func (mp *MPUnReachNLRI) String() string {
	var s string
	s += fmt.Sprintf("Address Family ID: %d\n", mp.AddressFamilyID)
	s += fmt.Sprintf("Subsequent Address Family ID: %d\n", mp.SubAddressFamilyID)

	return s
}

// MarshalJSON defines a custom method to convert MP REACH NLRI object into JSON object
func (mp *MPUnReachNLRI) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, []byte("{\"AddressFamilyID\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", mp.AddressFamilyID))...)
	jsonData = append(jsonData, []byte("\"SubAddressFamilyID\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d", mp.SubAddressFamilyID))...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalMPUnReachNLRI builds MP Reach NLRI attributes
func UnmarshalMPUnReachNLRI(b []byte) (*MPUnReachNLRI, error) {
	glog.V(6).Infof("MPUnReachNLRI Raw: %s", internal.MessageHex(b))
	mp := MPUnReachNLRI{}
	p := 0
	mp.AddressFamilyID = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	mp.SubAddressFamilyID = uint8(b[p])
	p++
	// Only SAFI 1 and 2 NLRI's carries []Route, other SAFI
	// may carry different type in NLRI, hence will require different decoding.
	switch mp.SubAddressFamilyID {
	case 1:
		fallthrough
	case 2:
		wdr, err := UnmarshalBGPRoutes(b)
		if err != nil {
			return nil, err
		}
		mp.WithdrawnRoutes = wdr
	}

	return &mp, nil
}
