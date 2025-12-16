package mcastvpn

import (
	"encoding/binary"
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// Type6 defines Shared Tree Join route (Route Type 6) - C-multicast
// RFC 6514 Section 4.6
// Format: RD (8 octets) + Source AS (4 octets) + Multicast Source Length (1 octet) +
//
//	Multicast Source (variable, contains C-RP address) + Multicast Group Length (1 octet) +
//	Multicast Group (variable)
type Type6 struct {
	RD                 *base.RD
	SourceAS           uint32
	MulticastSourceLen uint8
	MulticastSource    []byte // C-RP (Rendezvous Point) address
	MulticastGroupLen  uint8
	MulticastGroup     []byte
}

// UnmarshalType6 parses Shared Tree Join route
func UnmarshalType6(b []byte) (*Type6, error) {
	if len(b) < 14 {
		return nil, fmt.Errorf("invalid Type6 length: %d bytes (minimum 14)", len(b))
	}
	t := &Type6{}
	p := 0

	// Parse RD (8 bytes)
	rd, err := base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RD: %w", err)
	}
	t.RD = rd
	p += 8

	// Parse Source AS (4 bytes)
	if p+4 > len(b) {
		return nil, fmt.Errorf("not enough data for source AS at position %d", p)
	}
	t.SourceAS = binary.BigEndian.Uint32(b[p : p+4])
	p += 4

	// Parse Multicast Source Length (1 byte, in bits)
	if p >= len(b) {
		return nil, fmt.Errorf("missing multicast source length at position %d", p)
	}
	t.MulticastSourceLen = b[p]
	p++

	// Parse Multicast Source / C-RP (variable length based on bit length)
	sourceBytes := int((t.MulticastSourceLen + 7) / 8)
	if p+sourceBytes > len(b) {
		return nil, fmt.Errorf("not enough data for multicast source: need %d bytes at position %d", sourceBytes, p)
	}
	if sourceBytes > 0 {
		t.MulticastSource = make([]byte, sourceBytes)
		copy(t.MulticastSource, b[p:p+sourceBytes])
		p += sourceBytes
	}

	// Parse Multicast Group Length (1 byte, in bits)
	if p >= len(b) {
		return nil, fmt.Errorf("missing multicast group length at position %d", p)
	}
	t.MulticastGroupLen = b[p]
	p++

	// Parse Multicast Group (variable length based on bit length)
	groupBytes := int((t.MulticastGroupLen + 7) / 8)
	if p+groupBytes > len(b) {
		return nil, fmt.Errorf("not enough data for multicast group: need %d bytes at position %d", groupBytes, p)
	}
	if groupBytes > 0 {
		t.MulticastGroup = make([]byte, groupBytes)
		copy(t.MulticastGroup, b[p:p+groupBytes])
		p += groupBytes
	}

	// Verify we consumed all bytes
	if p != len(b) {
		return nil, fmt.Errorf("unexpected trailing bytes: consumed %d, total %d", p, len(b))
	}

	return t, nil
}

// GetRouteTypeSpec returns the route type specific structure
func (t *Type6) GetRouteTypeSpec() interface{} {
	return t
}

// getRD returns the Route Distinguisher
func (t *Type6) getRD() *base.RD {
	return t.RD
}

// getOriginatorIP returns nil (not applicable for Type 6)
func (t *Type6) getOriginatorIP() []byte {
	return nil
}

// getMulticastSource returns the Multicast Source / C-RP address
func (t *Type6) getMulticastSource() []byte {
	return t.MulticastSource
}

// getMulticastGroup returns the Multicast Group address
func (t *Type6) getMulticastGroup() []byte {
	return t.MulticastGroup
}

// getSourceAS returns the Source AS
func (t *Type6) getSourceAS() uint32 {
	return t.SourceAS
}
