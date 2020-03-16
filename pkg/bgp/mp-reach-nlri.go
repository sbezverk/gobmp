package bgp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
	"github.com/sbezverk/gobmp/pkg/ls"
)

// MPReachNLRI defines an MP Reach NLRI object
type MPReachNLRI struct {
	AddressFamilyID      uint16
	SubAddressFamilyID   uint8
	NextHopAddressLength uint8
	NextHopAddress       []byte
	Reserved             uint8
	NLRI                 []byte
}

func (mp *MPReachNLRI) String() string {
	var s string
	s += fmt.Sprintf("Address Family ID: %d\n", mp.AddressFamilyID)
	s += fmt.Sprintf("Subsequent Address Family ID: %d\n", mp.SubAddressFamilyID)
	if mp.NextHopAddressLength == 4 {
		s += fmt.Sprintf("Next Hop Network Address: %s\n", net.IP(mp.NextHopAddress).To4().String())
	} else if mp.NextHopAddressLength == 16 {
		s += fmt.Sprintf("Next Hop Network Address: %s\n", net.IP(mp.NextHopAddress).To16().String())
	}
	switch mp.SubAddressFamilyID {
	case 71:
		nlri, _ := ls.UnmarshalLSNLRI71(mp.NLRI)
		s += nlri.String()
	default:
		s += fmt.Sprintf("NLRI: %s\n", internal.MessageHex(mp.NLRI))
	}

	return s
}

// UnmarshalMPReachNLRI builds MP Reach NLRI attributes
func UnmarshalMPReachNLRI(b []byte) (*MPReachNLRI, error) {
	glog.V(6).Infof("MPReachNLRI Raw: %s", internal.MessageHex(b))
	mp := MPReachNLRI{}
	p := 0
	mp.AddressFamilyID = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	mp.SubAddressFamilyID = uint8(b[p])
	p++
	mp.NextHopAddressLength = uint8(b[p])
	p++
	mp.NextHopAddress = b[p : p+int(mp.NextHopAddressLength)]
	p += int(mp.NextHopAddressLength)
	// Skip reserved byte
	p++
	switch mp.SubAddressFamilyID {
	// TODO Define constants
	case 71:
		_, err := ls.UnmarshalLSNLRI71(b[p:len(b)])
		if err != nil {
			return nil, err
		}
	}
	mp.NLRI = b[p:len(b)]

	return &mp, nil
}
