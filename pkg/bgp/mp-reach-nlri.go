package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/evpn"
	"github.com/sbezverk/gobmp/pkg/flowspec"
	"github.com/sbezverk/gobmp/pkg/l3vpn"
	"github.com/sbezverk/gobmp/pkg/ls"
	"github.com/sbezverk/gobmp/pkg/mcastvpn"
	"github.com/sbezverk/gobmp/pkg/multicast"
	"github.com/sbezverk/gobmp/pkg/rtc"
	"github.com/sbezverk/gobmp/pkg/srpolicy"
	"github.com/sbezverk/gobmp/pkg/unicast"
	"github.com/sbezverk/gobmp/pkg/vpls"
	"github.com/sbezverk/tools"
)

// MPReachNLRI defines an MP Reach NLRI object
type MPReachNLRI struct {
	AddressFamilyID      uint16
	SubAddressFamilyID   uint8
	NextHopAddressLength uint8
	NextHopAddress       []byte
	NLRI                 []byte
	// When BGP update carries Prefix SID attribute 40, the processing of some AFI/SAFI NLRIs
	// may differ from the standard processing.
	SRv6    bool
	addPath map[int]bool
}

// GetAFISAFIType returns underlaying NLRI's type based on AFI/SAFI
func (mp *MPReachNLRI) GetAFISAFIType() int {
	return NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)
}

// IsIPv6NLRI return true if NLRI is for IPv6 address family
func (mp *MPReachNLRI) IsIPv6NLRI() bool {
	return mp.AddressFamilyID == 2
}

// IsNextHopIPv6 return true if the next hop is IPv6 address, otherwise it returns flase
func (mp *MPReachNLRI) IsNextHopIPv6() bool {
	// https://tools.ietf.org/id/draft-mishra-bess-ipv4nlri-ipv6nh-use-cases-00.html#rfc.section.3
	switch mp.NextHopAddressLength {
	case 16:
		fallthrough
	case 32:
		fallthrough
	case 24:
		fallthrough
	case 48:
		return true
	default:
		return false
	}
}

// GetNextHop return a string representation of the next hop ip address.
func (mp *MPReachNLRI) GetNextHop() string {
	switch mp.NextHopAddressLength {
	case 4:
		// IPv4
		return net.IP(mp.NextHopAddress).To4().String()
	case 8:
		// Peer 3 (Local-RIB) Next hop is 8 bytes RD 4 bytes and IPv4 address 4 bytes
		return net.IP(mp.NextHopAddress[4:]).To4().String()
	case 12:
		// RD (8 bytes) + IPv4
		return net.IP(mp.NextHopAddress[8:]).To4().String()
	case 16:
		// IPv6
		return net.IP(mp.NextHopAddress).To16().String()
	case 24:
		// RD (8 bytes) + IPv6
		return net.IP(mp.NextHopAddress[8:]).To16().String()
	case 32:
		// IPv6 + Link Local IPv6
		// https://tools.ietf.org/html/rfc2545#section-3
		return net.IP(mp.NextHopAddress[:16]).To16().String() + "," + net.IP(mp.NextHopAddress[16:]).To16().String()
	case 48:
		// RD:IPv6 + RD:Link Local IPv6
		return net.IP(mp.NextHopAddress[8:24]).To16().String() + "," + net.IP(mp.NextHopAddress[32:]).To16().String()
	}

	return "invalid next hop address length: " + strconv.Itoa(int(mp.NextHopAddressLength))
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

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_REACH_NLRI")
}

// GetNLRI73 check for presense of NLRI 73 in the NLRI 14 NLRI data and if exists, instantiate NLRI73 object
func (mp *MPReachNLRI) GetNLRI73() (*srpolicy.NLRI73, error) {
	if mp.SubAddressFamilyID == 73 {
		nlri73, err := srpolicy.UnmarshalLSNLRI73(mp.NLRI)
		if err != nil {
			return nil, err
		}
		return nlri73, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_REACH_NLRI")
}

// GetNLRIL3VPN check for presense of NLRI L3VPN AFI 1 and SAFI 128 in the NLRI 14 NLRI data and if exists, instantiate L3VPN object
func (mp *MPReachNLRI) GetNLRIL3VPN() (*base.MPNLRI, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 128 {
		pathID := mp.addPath[NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)]
		nlri, err := l3vpn.UnmarshalL3VPNNLRI(mp.NLRI, pathID, mp.SRv6)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_REACH_NLRI")
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

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_REACH_NLRI")
}

// GetNLRIVPLS check for presense of NLRI VPLS AFI 25 and SAFI 65 in the NLRI 14 NLRI data and if exists, instantiate VPLS object
func (mp *MPReachNLRI) GetNLRIVPLS() (*vpls.Route, error) {
	if mp.AddressFamilyID == 25 && mp.SubAddressFamilyID == 65 {
		route, err := vpls.UnmarshalVPLSNLRI(mp.NLRI)
		if err != nil {
			return nil, err
		}
		return route, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_REACH_NLRI")
}

// GetNLRIUnicast check for presense of NLRI EVPN AFI 1 or 2  and SAFI 1 in the NLRI 14 NLRI data and if exists, instantiate Unicast object
func (mp *MPReachNLRI) GetNLRIUnicast() (*base.MPNLRI, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 1 {
		pathID := mp.addPath[NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)]
		nlri, err := unicast.UnmarshalUnicastNLRI(mp.NLRI, pathID)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_REACH_NLRI")
}

// GetNLRIMulticast check for presense of NLRI Multicast AFI 1 or 2 and SAFI 2 in the NLRI 14 NLRI data and if exists, instantiate Multicast object
func (mp *MPReachNLRI) GetNLRIMulticast() (*base.MPNLRI, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 2 {
		pathID := mp.addPath[NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)]
		nlri, err := multicast.UnmarshalMulticastNLRI(mp.NLRI, pathID)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_REACH_NLRI")
}

// GetNLRILU check for presense of NLRI EVPN AFI 1 or 2  and SAFI 4 in the NLRI 14 NLRI data and if exists, instantiate Unicast object
func (mp *MPReachNLRI) GetNLRILU() (*base.MPNLRI, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 4 {
		pathID := mp.addPath[NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)]
		nlri, err := unicast.UnmarshalLUNLRI(mp.NLRI, pathID)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_REACH_NLRI")
}

// GetFlowspecNLRI checks for presense of NLRI 133 IPv4 Flowspec in the NLRI 14 NLRI data and if exists, instantiate NLRI object
func (mp *MPReachNLRI) GetFlowspecNLRI() (*flowspec.NLRI, error) {
	if mp.SubAddressFamilyID == 133 {
		return flowspec.UnmarshalFlowspecNLRI(mp.NLRI)
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_REACH_NLRI")
}

// GetNLRIMCASTVPN instantiates a MCAST-VPN NLRI structure based on passed slice
func (mp *MPReachNLRI) GetNLRIMCASTVPN() (*mcastvpn.Route, error) {
	if mp.SubAddressFamilyID == 5 {
		return mcastvpn.UnmarshalMCASTVPNNLRI(mp.NLRI)
	}

	return nil, fmt.Errorf("not found")
}

// GetNLRIMVPN instantiates Multicast VPN (SAFI 129) NLRI
func (mp *MPReachNLRI) GetNLRIMVPN() (*mcastvpn.Route, error) {
	if mp.SubAddressFamilyID == 129 {
		return mcastvpn.UnmarshalMCASTVPNNLRI(mp.NLRI)
	}

	return nil, fmt.Errorf("not found")
}

// GetNLRIRTC checks for presence of NLRI 132 Route Target Constraint in the NLRI 14 NLRI data and if exists, instantiate RTC NLRI object
func (mp *MPReachNLRI) GetNLRIRTC() (*rtc.Route, error) {
	if mp.SubAddressFamilyID == 132 {
		return rtc.UnmarshalRTCNLRI(mp.NLRI)
	}

	return nil, fmt.Errorf("not found")
}

// UnmarshalMPReachNLRI builds MP Reach NLRI attributes
func UnmarshalMPReachNLRI(b []byte, srv6 bool, addPath map[int]bool) (MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MPReachNLRI Raw: %s SRv6 flag: %t add path: %+v", tools.MessageHex(b), srv6, addPath)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	mp := MPReachNLRI{
		addPath: addPath,
		SRv6:    srv6,
	}
	p := 0
	mp.AddressFamilyID = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	mp.SubAddressFamilyID = uint8(b[p])
	p++
	mp.NextHopAddressLength = uint8(b[p])
	p++
	mp.NextHopAddress = make([]byte, mp.NextHopAddressLength)
	copy(mp.NextHopAddress, b[p:p+int(mp.NextHopAddressLength)])
	p += int(mp.NextHopAddressLength)
	// Skip reserved byte
	p++
	mp.NLRI = make([]byte, len(b[p:]))
	copy(mp.NLRI, b[p:])

	return &mp, nil
}
