package bgp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/evpn"
	"github.com/sbezverk/gobmp/pkg/l3vpn"
	"github.com/sbezverk/gobmp/pkg/ls"
	"github.com/sbezverk/gobmp/pkg/tools"
	"github.com/sbezverk/gobmp/pkg/unicast"
)

// MPReachNLRI defines an MP Reach NLRI object
type MPReachNLRI struct {
	AddressFamilyID      uint16
	SubAddressFamilyID   uint8
	NextHopAddressLength uint8
	NextHopAddress       []byte
	NLRI                 []byte
}

// GetAFISAFIType returns underlaying NLRI's type based on AFI/SAFI
func (mp *MPReachNLRI) GetAFISAFIType() int {
	return getNLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)
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

// IsIPv6NLRI return true if NLRI is for IPv6 address family
func (mp *MPReachNLRI) IsIPv6NLRI() bool {
	return mp.AddressFamilyID == 2
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
func (mp *MPReachNLRI) GetNLRIL3VPN() (*base.MPNLRI, error) {
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
func (mp *MPReachNLRI) GetNLRIEVPN() (*evpn.Route, error) {
	if mp.AddressFamilyID == 25 && mp.SubAddressFamilyID == 70 {
		route, err := evpn.UnmarshalEVPNNLRI(mp.NLRI)
		if err != nil {
			return nil, err
		}
		return route, nil
	}

	// TODO return new type of errors to be able to check for the code
	return nil, fmt.Errorf("not found")
}

// GetNLRIUnicast check for presense of NLRI EVPN AFI 1 or 2  and SAFI 1 in the NLRI 14 NLRI data and if exists, instantiate Unicast object
func (mp *MPReachNLRI) GetNLRIUnicast() (*base.MPNLRI, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 1 {
		nlri, err := unicast.UnmarshalUnicastNLRI(mp.NLRI)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	// TODO return new type of errors to be able to check for the code
	return nil, fmt.Errorf("not found")
}

// GetNLRILU check for presense of NLRI EVPN AFI 1 or 2  and SAFI 4 in the NLRI 14 NLRI data and if exists, instantiate Unicast object
func (mp *MPReachNLRI) GetNLRILU() (*base.MPNLRI, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 4 {
		nlri, err := unicast.UnmarshalLUNLRI(mp.NLRI)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	// TODO return new type of errors to be able to check for the code
	return nil, fmt.Errorf("not found")
}

// UnmarshalMPReachNLRI builds MP Reach NLRI attributes
func UnmarshalMPReachNLRI(b []byte) (MPNLRI, error) {
	glog.V(6).Infof("MPReachNLRI Raw: %s", tools.MessageHex(b))
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
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
	mp.NLRI = make([]byte, len(b[p:]))
	copy(mp.NLRI, b[p:])

	return &mp, nil
}
