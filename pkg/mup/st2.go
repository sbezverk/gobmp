package mup

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
)

// ST2Route defines the 3gpp-5g specific Type 2 Session Transformed route
// (Route Type 4) per draft Sections 3.1.4 and 3.1.4.1.
//
//	+-----------------------------------+
//	| RD  (8 octets)                    |
//	+-----------------------------------+
//	| Endpoint Length (1 octet)         |
//	+-----------------------------------+
//	| Endpoint Address (variable)       |
//	+-----------------------------------+
//	| TEID (0-4 octets)                 |
//	+-----------------------------------+
//	| TLVs (variable)                   |
//	+-----------------------------------+
//
// Endpoint Length covers the endpoint address plus the architecture specific
// endpoint identifier, so the number of TEID bits is Endpoint Length minus the
// width of the endpoint address.
type ST2Route struct {
	RD              *base.RD
	EndpointLength  uint8
	EndpointAddress []byte
	// TEID holds the significant TEID bits left aligned in a 4 octet field,
	// matching how they are carried on the wire. It is nil when the Endpoint
	// Length stops at the endpoint address, the route then carries no TEID.
	TEID *uint32
	TLVs []*TLV
}

// UnmarshalST2Route parses a Type 2 Session Transformed route
func UnmarshalST2Route(b []byte, ipv6 bool) (*ST2Route, error) {
	if len(b) < 9 {
		return nil, fmt.Errorf("not enough data for Type 2 Session Transformed route: need 9 bytes, have %d", len(b))
	}
	r := &ST2Route{}
	rd, err := base.MakeRD(b[0:8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RD: %w", err)
	}
	r.RD = rd
	p := 8
	r.EndpointLength = b[p]
	p++
	l := addrLen(ipv6)
	// Without the lower bound a too small Endpoint Length makes the TEID
	// length negative, which would hand the TEID octets to the TLV parser.
	if int(r.EndpointLength) < l*8 || int(r.EndpointLength) > l*8+32 {
		return nil, fmt.Errorf("invalid endpoint length %d (expected %d to %d)", r.EndpointLength, l*8, l*8+32)
	}
	if p+l > len(b) {
		return nil, fmt.Errorf("not enough data for Endpoint Address: need %d bytes, have %d", l, len(b)-p)
	}
	r.EndpointAddress = make([]byte, l)
	copy(r.EndpointAddress, b[p:p+l])
	p += l
	if teidBits := int(r.EndpointLength) - l*8; teidBits > 0 {
		byteLen := (teidBits + 7) / 8
		if p+byteLen > len(b) {
			return nil, fmt.Errorf("not enough data for TEID: need %d bytes, have %d", byteLen, len(b)-p)
		}
		b4 := make([]byte, 4)
		copy(b4, b[p:p+byteLen])
		maskPadding(b4, teidBits)
		teid := binary.BigEndian.Uint32(b4)
		if teid == 0 {
			return nil, fmt.Errorf("invalid TEID 0")
		}
		r.TEID = &teid
		p += byteLen
	}
	tlvs, err := unmarshalTLVs(b[p:])
	if err != nil {
		return nil, err
	}
	r.TLVs = tlvs

	return r, nil
}

// GetRouteTypeSpec returns the route type specific structure
func (r *ST2Route) GetRouteTypeSpec() interface{} {
	return r
}

// getRD returns the Route Distinguisher
func (r *ST2Route) getRD() *base.RD {
	return r.RD
}

// MarshalJSON renders a Type 2 Session Transformed route
func (r *ST2Route) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD              string  `json:"rd,omitempty"`
		EndpointAddress string  `json:"endpoint_address,omitempty"`
		EndpointLen     uint8   `json:"endpoint_len"`
		TEID            *uint32 `json:"teid,omitempty"`
		TLVs            []*TLV  `json:"tlvs,omitempty"`
	}{
		RD:              r.RD.String(),
		EndpointAddress: net.IP(r.EndpointAddress).String(),
		EndpointLen:     r.EndpointLength,
		TEID:            r.TEID,
		TLVs:            r.TLVs,
	})
}
