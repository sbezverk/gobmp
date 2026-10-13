package mup

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
)

// ISDRoute defines the Interwork Segment Discovery route (Route Type 1)
// per draft Section 3.1.1.
//
//	+-----------------------------------+
//	| RD  (8 octets)                    |
//	+-----------------------------------+
//	| Prefix Length (1 octet)           |
//	+-----------------------------------+
//	| Prefix (variable)                 |
//	+-----------------------------------+
type ISDRoute struct {
	RD           *base.RD
	PrefixLength uint8
	// Prefix is zero padded to the full width of the address family, the
	// wire encoding carries only the significant octets.
	Prefix []byte
}

// UnmarshalISDRoute parses an Interwork Segment Discovery route
func UnmarshalISDRoute(b []byte, ipv6 bool) (*ISDRoute, error) {
	if len(b) < 9 {
		return nil, fmt.Errorf("not enough data for Interwork Segment Discovery route: need 9 bytes, have %d", len(b))
	}
	r := &ISDRoute{}
	rd, err := base.MakeRD(b[0:8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RD: %w", err)
	}
	r.RD = rd
	r.PrefixLength = b[8]
	l := addrLen(ipv6)
	if int(r.PrefixLength) > l*8 {
		return nil, fmt.Errorf("invalid prefix length %d (maximum %d)", r.PrefixLength, l*8)
	}
	byteLen := (int(r.PrefixLength) + 7) / 8
	// The common header Length covers the whole route type specific field,
	// so anything past the prefix is not trailing padding but a malformed NLRI.
	if 9+byteLen != len(b) {
		return nil, fmt.Errorf("invalid prefix data length: need %d bytes, have %d", byteLen, len(b)-9)
	}
	r.Prefix = make([]byte, l)
	copy(r.Prefix, b[9:9+byteLen])
	maskPadding(r.Prefix, int(r.PrefixLength))

	return r, nil
}

// GetRouteTypeSpec returns the route type specific structure
func (r *ISDRoute) GetRouteTypeSpec() interface{} {
	return r
}

// getRD returns the Route Distinguisher
func (r *ISDRoute) getRD() *base.RD {
	return r.RD
}

// MarshalJSON renders an Interwork Segment Discovery route
func (r *ISDRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD        string `json:"rd,omitempty"`
		Prefix    string `json:"prefix,omitempty"`
		PrefixLen uint8  `json:"prefix_len"`
	}{
		RD:        r.RD.String(),
		Prefix:    net.IP(r.Prefix).String(),
		PrefixLen: r.PrefixLength,
	})
}
