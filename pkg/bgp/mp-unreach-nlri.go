package bgp

import (
	"encoding/binary"
	"fmt"

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

// MPUnReachNLRI defines an MP UnReach NLRI object
type MPUnReachNLRI struct {
	AddressFamilyID    uint16
	SubAddressFamilyID uint8
	WithdrawnRoutes    []byte
	addPath            map[int]bool
	SRv6               bool
}

// GetAFISAFIType returns underlaying NLRI's type based on AFI/SAFI
func (mp *MPUnReachNLRI) GetAFISAFIType() int {
	return NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)
}

// IsIPv6NLRI return true if NLRI is for IPv6 address family
func (mp *MPUnReachNLRI) IsIPv6NLRI() bool {
	return mp.AddressFamilyID == 2
}

// GetNextHop return a string representation of the next hop ip address.
func (mp *MPUnReachNLRI) GetNextHop() string {
	return ""
}

// IsNextHopIPv6 returns true if the next hop is IPv6 address, otherwise it returns false.
// in case of MP_UNREACH_NLRI there is no Next Hop field and this function should not be used.
func (mp *MPUnReachNLRI) IsNextHopIPv6() bool {
	return false
}

// GetNLRI71 check for presence of NLRI 71 in the NLRI 15 NLRI data and if exists, instantiate NLRI71 object
func (mp *MPUnReachNLRI) GetNLRI71() (*ls.NLRI71, error) {
	if mp.AddressFamilyID == 16388 && mp.SubAddressFamilyID == 71 {
		pathID := mp.addPath[NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)]
		nlri71, err := ls.UnmarshalLSNLRI71(mp.WithdrawnRoutes, pathID)
		if err != nil {
			return nil, err
		}
		return nlri71, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetNLRI73 check for presence of NLRI 73 in the NLRI 15 NLRI data and if exists, instantiate NLRI73 object
func (mp *MPUnReachNLRI) GetNLRI73() (*srpolicy.NLRI73, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 73 {
		nlri73, err := srpolicy.UnmarshalLSNLRI73(mp.WithdrawnRoutes)
		if err != nil {
			return nil, err
		}
		return nlri73, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetNLRIL3VPN check for presence of NLRI L3VPN AFI 1/2 and SAFI 128 in the NLRI 15 NLRI data and if exists, instantiate L3VPN object
func (mp *MPUnReachNLRI) GetNLRIL3VPN() (*base.MPNLRI, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 128 {
		pathID := mp.addPath[NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)]
		nlri, err := l3vpn.UnmarshalL3VPNNLRI(mp.WithdrawnRoutes, pathID, mp.SRv6)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetNLRIEVPN check for presence of NLRI EVPN AFI 25 and SAFI 70 in the NLRI 15 NLRI data and if exists, instantiate EVPN object
func (mp *MPUnReachNLRI) GetNLRIEVPN() (*evpn.Route, error) {
	if mp.AddressFamilyID == 25 && mp.SubAddressFamilyID == 70 {
		route, err := evpn.UnmarshalEVPNNLRI(mp.WithdrawnRoutes)
		if err != nil {
			return nil, err
		}
		return route, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetNLRIVPLS check for presence of NLRI VPLS AFI 25 and SAFI 65 in the NLRI 15 NLRI data and if exists, instantiate VPLS object
func (mp *MPUnReachNLRI) GetNLRIVPLS() (*vpls.Route, error) {
	if mp.AddressFamilyID == 25 && mp.SubAddressFamilyID == 65 {
		route, err := vpls.UnmarshalVPLSNLRI(mp.WithdrawnRoutes)
		if err != nil {
			return nil, err
		}
		return route, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetNLRIUnicast check for presence of Unicast AFI 1 or 2 and SAFI 1 in the MP_UNREACH_NLRI data and if exists, instantiate Unicast object
func (mp *MPUnReachNLRI) GetNLRIUnicast() (*base.MPNLRI, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 1 {
		pathID := mp.addPath[NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)]
		nlri, err := unicast.UnmarshalUnicastNLRI(mp.WithdrawnRoutes, pathID)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetNLRIMulticast check for presence of NLRI Multicast AFI 1 or 2 and SAFI 2 in the NLRI 15 NLRI data and if exists, instantiate Multicast object
func (mp *MPUnReachNLRI) GetNLRIMulticast() (*base.MPNLRI, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 2 {
		pathID := mp.addPath[NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)]
		nlri, err := multicast.UnmarshalMulticastNLRI(mp.WithdrawnRoutes, pathID)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetNLRILU check for presence of Labeled Unicast AFI 1 or 2 and SAFI 4 in the MP_UNREACH_NLRI data and if exists, instantiate LU object
func (mp *MPUnReachNLRI) GetNLRILU() (*base.MPNLRI, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 4 {
		pathID := mp.addPath[NLRIMessageType(mp.AddressFamilyID, mp.SubAddressFamilyID)]
		nlri, err := unicast.UnmarshalLUNLRI(mp.WithdrawnRoutes, pathID)
		if err != nil {
			return nil, err
		}
		return nlri, nil
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetFlowspecNLRI checks for presence of Flowspec (SAFI=133) in MP_UNREACH_NLRI and parses the first withdrawn route.
// Returns nil NLRI with nil error for empty withdrawn routes (withdraw-all signal).
// Use GetAllFlowspecNLRI to parse multiple NLRIs per RFC 8955/8956.
func (mp *MPUnReachNLRI) GetFlowspecNLRI() (*flowspec.NLRI, error) {
	if mp.SubAddressFamilyID == 133 && (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) {
		if len(mp.WithdrawnRoutes) == 0 {
			// RFC 8955 §4 / RFC 8956 §3: empty MP_UNREACH_NLRI is a withdraw-all signal.
			return nil, nil
		}
		if mp.AddressFamilyID == 2 {
			return flowspec.UnmarshalIPv6FlowspecNLRI(mp.WithdrawnRoutes)
		}
		return flowspec.UnmarshalFlowspecNLRI(mp.WithdrawnRoutes)
	}
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 134 {
		if len(mp.WithdrawnRoutes) == 0 {
			return nil, nil
		}
		return flowspec.UnmarshalVPNFlowspecNLRI(mp.WithdrawnRoutes, mp.AddressFamilyID == 2)
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetAllFlowspecNLRI parses all Flowspec NLRIs from MP_UNREACH_NLRI.
// Supports IPv4 (AFI=1, RFC 8955), IPv6 (AFI=2, RFC 8956), and VPN (SAFI=134, RFC 8955 §6).
// Returns nil slice with nil error for empty withdrawn routes (withdraw-all).
func (mp *MPUnReachNLRI) GetAllFlowspecNLRI() ([]*flowspec.NLRI, error) {
	if mp.AddressFamilyID == 1 && mp.SubAddressFamilyID == 133 {
		return flowspec.UnmarshalAllFlowspecNLRI(mp.WithdrawnRoutes)
	}
	if mp.AddressFamilyID == 2 && mp.SubAddressFamilyID == 133 {
		return flowspec.UnmarshalAllIPv6FlowspecNLRI(mp.WithdrawnRoutes)
	}
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 134 {
		return flowspec.UnmarshalAllVPNFlowspecNLRI(mp.WithdrawnRoutes, mp.AddressFamilyID == 2)
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetNLRIMCASTVPN instantiates a MCAST-VPN NLRI structure based on withdrawn routes
func (mp *MPUnReachNLRI) GetNLRIMCASTVPN() (*mcastvpn.Route, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 5 {
		return mcastvpn.UnmarshalMCASTVPNNLRI(mp.WithdrawnRoutes, mp.AddressFamilyID == 2)
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetNLRIMVPN instantiates Multicast VPN (SAFI 129) NLRI
func (mp *MPUnReachNLRI) GetNLRIMVPN() (*mcastvpn.Route, error) {
	if (mp.AddressFamilyID == 1 || mp.AddressFamilyID == 2) && mp.SubAddressFamilyID == 129 {
		return mcastvpn.UnmarshalMCASTVPNNLRI(mp.WithdrawnRoutes, mp.AddressFamilyID == 2)
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// GetNLRIRTC checks for presence of NLRI 132 Route Target Constraint in the NLRI 15 NLRI data and if exists, instantiate RTC NLRI object
func (mp *MPUnReachNLRI) GetNLRIRTC() (*rtc.Route, error) {
	if mp.SubAddressFamilyID == 132 {
		return rtc.UnmarshalRTCNLRI(mp.WithdrawnRoutes)
	}

	return nil, NewNLRINotFoundError(mp.AddressFamilyID, mp.SubAddressFamilyID, "MP_UNREACH_NLRI")
}

// UnmarshalMPUnReachNLRI builds MP UnReach NLRI attributes
func UnmarshalMPUnReachNLRI(b []byte, addPath map[int]bool, srv6 ...bool) (MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MPUnReachNLRI Raw: %s", tools.MessageHex(b))
	}
	mp := MPUnReachNLRI{
		addPath: addPath,
	}
	if len(srv6) > 0 {
		mp.SRv6 = srv6[0]
	}
	p := 0
	if p+3 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal MP_UNREACH_NLRI: need at least 3 bytes, have %d (remaining at offset %d)", len(b)-p, p)
	}
	mp.AddressFamilyID = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	mp.SubAddressFamilyID = uint8(b[p])
	p++
	mp.WithdrawnRoutes = make([]byte, len(b[p:]))
	copy(mp.WithdrawnRoutes, b[p:])

	return &mp, nil
}
