package mcastvpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// Type3 defines S-PMSI A-D route (Route Type 3)
// RFC 6514 Section 4.3
// Format: RD (8 octets) + Multicast Source Length (1 octet) + Multicast Source (variable) +
//
//	Multicast Group Length (1 octet) + Multicast Group (variable) + Originating Router's IP (variable)
type Type3 struct {
	RD                 *base.RD
	MulticastSourceLen uint8
	MulticastSource    []byte
	MulticastGroupLen  uint8
	MulticastGroup     []byte
	OriginatorIP       []byte
}

// UnmarshalType3 parses S-PMSI A-D route
func UnmarshalType3(b []byte) (*Type3, error) {
	if len(b) < 10 {
		return nil, fmt.Errorf("invalid Type3 length: %d bytes (minimum 10)", len(b))
	}
	t := &Type3{}
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

	// Parse Originating Router's IP Address (remaining bytes: 4 for IPv4, 16 for IPv6)
	remaining := len(b) - p
	if remaining != 4 && remaining != 16 {
		return nil, fmt.Errorf("invalid originating router IP length: %d bytes (expected 4 or 16)", remaining)
	}
	t.OriginatorIP = make([]byte, remaining)
	copy(t.OriginatorIP, b[p:p+remaining])

	return t, nil
}

// GetRouteTypeSpec returns the route type specific structure
func (t *Type3) GetRouteTypeSpec() interface{} {
	return t
}

// getRD returns the Route Distinguisher
func (t *Type3) getRD() *base.RD {
	return t.RD
}

// getOriginatorIP returns the Originating Router's IP address
func (t *Type3) getOriginatorIP() []byte {
	return t.OriginatorIP
}

// getMulticastSource returns the Multicast Source address
func (t *Type3) getMulticastSource() []byte {
	return t.MulticastSource
}

// getMulticastGroup returns the Multicast Group address
func (t *Type3) getMulticastGroup() []byte {
	return t.MulticastGroup
}

// getSourceAS returns 0 (not applicable for Type 3)
func (t *Type3) getSourceAS() uint32 {
	return 0
}
