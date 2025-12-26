package vpls

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// unmarshalRFC6074NLRI parses RFC 6074 BGP-AD NLRI (12 bytes)
//
// RFC 6074 NLRI Format:
//
//	+------------------------------------+
//	|  Length (2 octets)                 | <-- handled by caller
//	+------------------------------------+
//	|  Route Distinguisher (8 octets)    | offset 0-7
//	+------------------------------------+
//	|  PE Address (4 octets)             | offset 8-11 (IPv4 only)
//	+------------------------------------+
//
// Note: RFC 6074 Section 5 specifies IPv4 PE address only
func unmarshalRFC6074NLRI(b []byte) (*NLRI, error) {
	// RFC 6074 Section 5: NLRI must be exactly 12 bytes
	if len(b) != 12 {
		return nil, fmt.Errorf("RFC 6074 NLRI must be 12 bytes, got %d", len(b))
	}

	nlri := &NLRI{
		RFCType: "RFC6074",
	}

	// Parse Route Distinguisher (8 bytes, offset 0-7)
	rd, err := base.MakeRD(b[0:8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Route Distinguisher: %w", err)
	}
	nlri.RD = rd

	// Parse PE Address (4 bytes, offset 8-11)
	// RFC 6074 Section 5: IPv4 address of the advertising PE
	peAddr, err := formatIPv4(b[8:12])
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE address: %w", err)
	}
	nlri.PEAddr = &peAddr

	return nlri, nil
}
