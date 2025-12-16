package mcastvpn

import (
	"encoding/binary"
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// Type2 defines Inter-AS I-PMSI A-D route (Route Type 2)
// RFC 6514 Section 4.2
// Format: RD (8 octets) + Source AS (4 octets)
type Type2 struct {
	RD       *base.RD
	SourceAS uint32
}

// UnmarshalType2 parses Inter-AS I-PMSI A-D route
func UnmarshalType2(b []byte) (*Type2, error) {
	if len(b) != 12 {
		return nil, fmt.Errorf("invalid Type2 length: %d bytes (expected 12)", len(b))
	}
	t := &Type2{}
	p := 0

	// Parse RD (8 bytes)
	rd, err := base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RD: %w", err)
	}
	t.RD = rd
	p += 8

	// Parse Source AS (4 bytes)
	t.SourceAS = binary.BigEndian.Uint32(b[p : p+4])

	return t, nil
}

// GetRouteTypeSpec returns the route type specific structure
func (t *Type2) GetRouteTypeSpec() interface{} {
	return t
}

// getRD returns the Route Distinguisher
func (t *Type2) getRD() *base.RD {
	return t.RD
}

// getOriginatorIP returns nil (not applicable for Type 2)
func (t *Type2) getOriginatorIP() []byte {
	return nil
}

// getMulticastSource returns nil (not applicable for Type 2)
func (t *Type2) getMulticastSource() []byte {
	return nil
}

// getMulticastGroup returns nil (not applicable for Type 2)
func (t *Type2) getMulticastGroup() []byte {
	return nil
}

// getSourceAS returns the Source AS
func (t *Type2) getSourceAS() uint32 {
	return t.SourceAS
}
