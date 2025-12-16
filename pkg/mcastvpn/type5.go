package mcastvpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// Type5 defines Source Active A-D route (Route Type 5)
// RFC 6514 Section 4.5
// Format: RD (8 octets) + Multicast Source Length (1 octet) + Multicast Source (variable) +
//
//	Multicast Group Length (1 octet) + Multicast Group (variable)
type Type5 struct {
	RD                 *base.RD
	MulticastSourceLen uint8
	MulticastSource    []byte
	MulticastGroupLen  uint8
	MulticastGroup     []byte
}

// UnmarshalType5 parses Source Active A-D route
func UnmarshalType5(b []byte) (*Type5, error) {
	if len(b) < 10 {
		return nil, fmt.Errorf("invalid Type5 length: %d bytes (minimum 10)", len(b))
	}
	t := &Type5{}
	p := 0

	// Parse RD (8 bytes)
	rd, err := base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RD: %w", err)
	}
	t.RD = rd
	p += 8

	// Parse Multicast Source Length (1 byte, in bits)
	if p >= len(b) {
		return nil, fmt.Errorf("missing multicast source length at position %d", p)
	}
	t.MulticastSourceLen = b[p]
	p++

	// Parse Multicast Source (variable length based on bit length)
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
func (t *Type5) GetRouteTypeSpec() interface{} {
	return t
}

// getRD returns the Route Distinguisher
func (t *Type5) getRD() *base.RD {
	return t.RD
}

// getOriginatorIP returns nil (not applicable for Type 5)
func (t *Type5) getOriginatorIP() []byte {
	return nil
}

// getMulticastSource returns the Multicast Source address
func (t *Type5) getMulticastSource() []byte {
	return t.MulticastSource
}

// getMulticastGroup returns the Multicast Group address
func (t *Type5) getMulticastGroup() []byte {
	return t.MulticastGroup
}

// getSourceAS returns 0 (not applicable for Type 5)
func (t *Type5) getSourceAS() uint32 {
	return 0
}
