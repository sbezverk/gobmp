package mup

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
)

// DSDRoute defines the Direct Segment Discovery route (Route Type 2)
// per draft Section 3.1.2.
//
//	+-----------------------------------+
//	| RD  (8 octets)                    |
//	+-----------------------------------+
//	| Address (4 or 16 octets)          |
//	+-----------------------------------+
type DSDRoute struct {
	RD      *base.RD
	Address []byte
}

// UnmarshalDSDRoute parses a Direct Segment Discovery route
func UnmarshalDSDRoute(b []byte, ipv6 bool) (*DSDRoute, error) {
	l := addrLen(ipv6)
	// The draft has no length field here, the address length is fully
	// determined by the AFI, so anything else is a malformed NLRI.
	if len(b) != 8+l {
		return nil, fmt.Errorf("invalid Direct Segment Discovery route length: need %d bytes, have %d", 8+l, len(b))
	}
	r := &DSDRoute{}
	rd, err := base.MakeRD(b[0:8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RD: %w", err)
	}
	r.RD = rd
	r.Address = make([]byte, l)
	copy(r.Address, b[8:8+l])

	return r, nil
}

// GetRouteTypeSpec returns the route type specific structure
func (r *DSDRoute) GetRouteTypeSpec() interface{} {
	return r
}

// getRD returns the Route Distinguisher
func (r *DSDRoute) getRD() *base.RD {
	return r.RD
}

// MarshalJSON renders a Direct Segment Discovery route
func (r *DSDRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD      string `json:"rd,omitempty"`
		Address string `json:"address,omitempty"`
	}{
		RD:      r.RD.String(),
		Address: net.IP(r.Address).String(),
	})
}
