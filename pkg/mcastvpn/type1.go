package mcastvpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// Type1 defines Intra-AS I-PMSI A-D route (Route Type 1)
// RFC 6514 Section 4.1
// Format: RD (8 octets) + Originating Router's IP Address (4 or 16 octets)
type Type1 struct {
	RD           *base.RD
	OriginatorIP []byte
}

// UnmarshalType1 parses Intra-AS I-PMSI A-D route
func UnmarshalType1(b []byte) (*Type1, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("invalid Type1 length: %d bytes (minimum 12)", len(b))
	}
	t := &Type1{}
	p := 0

	// Parse RD (8 bytes)
	rd, err := base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RD: %w", err)
	}
	t.RD = rd
	p += 8

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
func (t *Type1) GetRouteTypeSpec() interface{} {
	return t
}

// getRD returns the Route Distinguisher
func (t *Type1) getRD() *base.RD {
	return t.RD
}

// getOriginatorIP returns the Originating Router's IP address
func (t *Type1) getOriginatorIP() []byte {
	return t.OriginatorIP
}

// getMulticastSource returns nil (not applicable for Type 1)
func (t *Type1) getMulticastSource() []byte {
	return nil
}

// getMulticastGroup returns nil (not applicable for Type 1)
func (t *Type1) getMulticastGroup() []byte {
	return nil
}

// getSourceAS returns 0 (not applicable for Type 1)
func (t *Type1) getSourceAS() uint32 {
	return 0
}
