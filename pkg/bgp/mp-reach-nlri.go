package bgp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/evpn"
	"github.com/sbezverk/gobmp/pkg/l3vpn"
	"github.com/sbezverk/gobmp/pkg/ls"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// MPReachNLRI defines an MP Reach NLRI object
type MPReachNLRI struct {
	AddressFamilyID      uint16
	SubAddressFamilyID   uint8
	NextHopAddressLength uint8
	NextHopAddress       []byte
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
		nlri, err := ls.UnmarshalLSNLRI71(mp.NLRI)
		if err != nil {
			s += err.Error()
		} else {
			s += nlri.String()
		}
	default:
		s += fmt.Sprintf("NLRI: %s\n", tools.MessageHex(mp.NLRI))
	}

	return s
}

// GetNextHop return a string representation of the next hop ip address.
func (mp *MPReachNLRI) GetNextHop() string {
	if mp.AddressFamilyID == 1 && mp.SubAddressFamilyID == 128 {
		// In case of L3VPN AFI 1 SAFI 128, next hop is encoded as RD (Always 0, 8 bytes) + ipv4 address
		return net.IP(mp.NextHopAddress[mp.NextHopAddressLength-4:]).To4().String()
	}
	if mp.NextHopAddressLength == 4 {
		return net.IP(mp.NextHopAddress).To4().String()
	} else if mp.NextHopAddressLength == 16 {
		return net.IP(mp.NextHopAddress).To16().String()
	}
	return "invalid"
}

// GetNLRI71 check for presense of NLRI 71 in the NLRI 14 NLRI data and if exists, instantiate NLRI71 object
func (mp *MPReachNLRI) GetNLRI71() (*ls.NLRI71, error) {
	if mp.SubAddressFamilyID == 71 {
		nlri71, err := ls.UnmarshalLSNLRI71(mp.NLRI)
		if err != nil {
			return nil, err
		}
		return nlri71, nil
	}

	// TODO return new type of errors to be able to check for the code
	return nil, fmt.Errorf("not found")
}

// GetNLRIL3VPN check for presense of NLRI L3VPN AFI 1 and SAFI 128 in the NLRI 14 NLRI data and if exists, instantiate L3VPN object
func (mp *MPReachNLRI) GetNLRIL3VPN() (*l3vpn.NLRI, error) {
	if mp.AddressFamilyID == 1 && mp.SubAddressFamilyID == 128 {
		nlri, err := l3vpn.UnmarshalL3VPNNLRI(mp.NLRI)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	// TODO return new type of errors to be able to check for the code
	return nil, fmt.Errorf("not found")
}

// GetNLRIEVPN check for presense of NLRI EVPN AFI 25 and SAFI 70 in the NLRI 14 NLRI data and if exists, instantiate EVPN object
func (mp *MPReachNLRI) GetNLRIEVPN() (*evpn.NLRI, error) {
	if mp.AddressFamilyID == 25 && mp.SubAddressFamilyID == 70 {
		nlri, err := evpn.UnmarshalEVPNNLRI(mp.NLRI)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	// TODO return new type of errors to be able to check for the code
	return nil, fmt.Errorf("not found")
}

// UnmarshalMPReachNLRI builds MP Reach NLRI attributes
func UnmarshalMPReachNLRI(b []byte) (*MPReachNLRI, error) {
	glog.V(6).Infof("MPReachNLRI Raw: %s", tools.MessageHex(b))
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
	mp.NLRI = make([]byte, len(b)-p)
	copy(mp.NLRI, b[p:])

	return &mp, nil
}
