package mup

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
)

// ST1Route defines the 3gpp-5g specific Type 1 Session Transformed route
// (Route Type 3) per draft Sections 3.1.3 and 3.1.3.1.
//
//	+-----------------------------------+
//	| RD  (8 octets)                    |
//	+-----------------------------------+
//	| Prefix Length (1 octet)           |
//	+-----------------------------------+
//	| Prefix (variable)                 |
//	+-----------------------------------+
//	| TEID (4 octets)                   |
//	+-----------------------------------+
//	| QFI (1 octet)                     |
//	+-----------------------------------+
//	| Endpoint Address Length (1 octet) |
//	+-----------------------------------+
//	| Endpoint Address (variable)       |
//	+-----------------------------------+
//	| Source Address Length (1 octet)   |
//	+-----------------------------------+
//	| Source Address (variable)         |
//	+-----------------------------------+
//	| TLVs (variable)                   |
//	+-----------------------------------+
type ST1Route struct {
	RD           *base.RD
	PrefixLength uint8
	// Prefix is zero padded to the full width of the address family, the
	// wire encoding carries only the significant octets.
	Prefix                []byte
	TEID                  uint32
	QFI                   uint8
	EndpointAddressLength uint8
	EndpointAddress       []byte
	SourceAddressLength   uint8
	// SourceAddress is nil when SourceAddressLength is 0, the draft leaves
	// the source address to local configuration in that case.
	SourceAddress []byte
	TLVs          []*TLV
}

// UnmarshalST1Route parses a Type 1 Session Transformed route
func UnmarshalST1Route(b []byte, ipv6 bool) (*ST1Route, error) {
	if len(b) < 9 {
		return nil, fmt.Errorf("not enough data for Type 1 Session Transformed route: need 9 bytes, have %d", len(b))
	}
	r := &ST1Route{}
	rd, err := base.MakeRD(b[0:8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RD: %w", err)
	}
	r.RD = rd
	p := 8
	r.PrefixLength = b[p]
	p++
	l := addrLen(ipv6)
	if int(r.PrefixLength) > l*8 {
		return nil, fmt.Errorf("invalid prefix length %d (maximum %d)", r.PrefixLength, l*8)
	}
	byteLen := (int(r.PrefixLength) + 7) / 8
	if p+byteLen > len(b) {
		return nil, fmt.Errorf("not enough data for prefix: need %d bytes, have %d", byteLen, len(b)-p)
	}
	r.Prefix = make([]byte, l)
	copy(r.Prefix, b[p:p+byteLen])
	maskPadding(r.Prefix, int(r.PrefixLength))
	p += byteLen
	// TEID (4) + QFI (1) + Endpoint Address Length (1)
	if p+6 > len(b) {
		return nil, fmt.Errorf("not enough data for TEID, QFI and Endpoint Address Length: need 6 bytes, have %d", len(b)-p)
	}
	r.TEID = binary.BigEndian.Uint32(b[p : p+4])
	if r.TEID == 0 {
		return nil, fmt.Errorf("invalid TEID 0")
	}
	p += 4
	r.QFI = b[p]
	p++
	r.EndpointAddressLength = b[p]
	p++
	// The endpoint sits on the GTP-U side, so its address family is carried
	// by the length field rather than derived from the NLRI AFI.
	if r.EndpointAddressLength != 32 && r.EndpointAddressLength != 128 {
		return nil, fmt.Errorf("invalid endpoint address length %d (expected 32 or 128)", r.EndpointAddressLength)
	}
	eaLen := int(r.EndpointAddressLength) / 8
	if p+eaLen+1 > len(b) {
		return nil, fmt.Errorf("not enough data for Endpoint Address and Source Address Length: need %d bytes, have %d", eaLen+1, len(b)-p)
	}
	r.EndpointAddress = make([]byte, eaLen)
	copy(r.EndpointAddress, b[p:p+eaLen])
	p += eaLen
	r.SourceAddressLength = b[p]
	p++
	// Any other length would leave the TLVs below read from a wrong offset.
	switch r.SourceAddressLength {
	case 0:
	case 32, 128:
		saLen := int(r.SourceAddressLength) / 8
		if p+saLen > len(b) {
			return nil, fmt.Errorf("not enough data for Source Address: need %d bytes, have %d", saLen, len(b)-p)
		}
		r.SourceAddress = make([]byte, saLen)
		copy(r.SourceAddress, b[p:p+saLen])
		p += saLen
	default:
		return nil, fmt.Errorf("invalid source address length %d (expected 0, 32 or 128)", r.SourceAddressLength)
	}
	// None of the TLVs draft Section 3.1.5 defines applies to a Type 1 ST
	// route, and a TLV received by a route type it does not apply to MUST be
	// ignored. The framing is still validated, Section 3.1.3.1 makes a TLV
	// parsing error a malformed NLRI, TLVs are kept to provide lossless
	// monitoring or future-extension visibility.
	tlvs, err := unmarshalTLVs(b[p:])
	if err != nil {
		return nil, err
	}
	r.TLVs = tlvs

	return r, nil
}

// GetRouteTypeSpec returns the route type specific structure
func (r *ST1Route) GetRouteTypeSpec() interface{} {
	return r
}

// getRD returns the Route Distinguisher
func (r *ST1Route) getRD() *base.RD {
	return r.RD
}

// MarshalJSON renders a Type 1 Session Transformed route
func (r *ST1Route) MarshalJSON() ([]byte, error) {
	v := struct {
		RD              string `json:"rd,omitempty"`
		Prefix          string `json:"prefix,omitempty"`
		PrefixLen       uint8  `json:"prefix_len"`
		TEID            uint32 `json:"teid"`
		QFI             uint8  `json:"qfi"`
		EndpointAddress string `json:"endpoint_address,omitempty"`
		EndpointLen     uint8  `json:"endpoint_len"`
		SourceAddress   string `json:"source_address,omitempty"`
		TLVs            []*TLV `json:"tlvs,omitempty"`
	}{
		RD:              r.RD.String(),
		Prefix:          net.IP(r.Prefix).String(),
		PrefixLen:       r.PrefixLength,
		TEID:            r.TEID,
		QFI:             r.QFI,
		EndpointAddress: net.IP(r.EndpointAddress).String(),
		EndpointLen:     r.EndpointAddressLength,
		TLVs:            r.TLVs,
	}
	if r.SourceAddress != nil {
		v.SourceAddress = net.IP(r.SourceAddress).String()
	}
	return json.Marshal(&v)
}
