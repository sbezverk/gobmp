package bgp

import (
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/evpn"
	"github.com/sbezverk/gobmp/pkg/ls"
)

// MPNLRI defines a common interface methind for MP Reach and MP Unreach NLRIs
type MPNLRI interface {
	GetAFISAFIType() int
	GetNLRILU() (*base.MPNLRI, error)
	GetNLRIUnicast() (*base.MPNLRI, error)
	GetNLRIEVPN() (*evpn.Route, error)
	GetNLRIL3VPN() (*base.MPNLRI, error)
	GetNLRI71() (*ls.NLRI71, error)
	GetNextHop() string
	IsIPv6NLRI() bool
	IsNextHopIPv6() bool
}

func getNLRIMessageType(afi uint16, safi uint8) int {
	switch {
	// 16388 BGP-LS	[RFC7752] : 71	BGP-LS	[RFC7752]
	case afi == 16388 && safi == 71:
		return 71
	// 1 IP (IP version 4) : 1 unicast forwarding
	case afi == 1 && safi == 1:
		return 1
	// 2 IP6 (IP version 6) : 1 unicast forwarding
	case afi == 2 && safi == 1:
		return 2
	// 1 IP (IP version 4) : 4 MPLS Labels
	case afi == 1 && safi == 4:
		return 16
	// 2 IP (IP version 6) : 4 MPLS Labels
	case afi == 2 && safi == 4:
		return 17
	// 1 IP (IP version 4) : 128 MPLS-labeled VPN address
	case afi == 1 && safi == 128:
		return 18
	// 2 IP (IP version 6) : 128 MPLS-labeled VPN address
	case afi == 2 && safi == 128:
		return 19
	// AFI of 25 (L2VPN) and a SAFI of 65 (VPLS)
	case afi == 25 && safi == 65:
		return 23
	// AFI of 25 (L2VPN) and a SAFI of 70 (EVPN)
	case afi == 25 && safi == 70:
		return 24
	}

	return 0
}
