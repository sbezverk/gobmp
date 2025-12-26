// Package vpls implements parsers for VPLS (Virtual Private LAN Service) NLRI.
//
// Supports both RFC 4761 (VPLS-BGP) and RFC 6074 (BGP-AD) specifications:
//   - RFC 4761: 17-byte NLRI with VE ID and MPLS label blocks
//   - RFC 6074: 12-byte NLRI with PE IPv4 address
//
// The package automatically demultiplexes between RFC formats based on NLRI length.
package vpls

import (
	"encoding/binary"
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// Route defines a collection of VPLS NLRI objects
type Route struct {
	Route []*NLRI
}

// NLRI defines a single VPLS NLRI object
// Supports both RFC 4761 (17 bytes) and RFC 6074 (12 bytes) formats
type NLRI struct {
	Length  uint16
	RFCType string // "RFC4761" or "RFC6074"
	RD      *base.RD

	// RFC 4761 fields (17-byte format)
	VEID          *uint16 // Virtual Edge ID
	VEBlockOffset *uint16 // VE Block Offset
	VEBlockSize   *uint16 // VE Block Size
	LabelBase     *uint32 // 20-bit MPLS label

	// RFC 6074 fields (12-byte format)
	PEAddr *string // IPv4 address
}

// UnmarshalVPLSNLRI builds a collection of VPLS NLRIs from the byte slice
// Demultiplexes RFC 4761 vs RFC 6074 based on NLRI length (17 vs 12 bytes)
func UnmarshalVPLSNLRI(b []byte) (*Route, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}

	r := &Route{
		Route: make([]*NLRI, 0),
	}

	for p := 0; p < len(b); {
		// Check if we have at least 2 bytes for length field
		if p+2 > len(b) {
			return nil, fmt.Errorf("incomplete NLRI at offset %d: need 2 bytes for length, have %d", p, len(b)-p)
		}

		// Read NLRI length (2 bytes)
		length := binary.BigEndian.Uint16(b[p : p+2])
		p += 2

		// Verify we have enough bytes for the NLRI
		if p+int(length) > len(b) {
			return nil, fmt.Errorf("incomplete NLRI at offset %d: length=%d, available=%d", p-2, length, len(b)-p)
		}

		var nlri *NLRI
		var err error

		// Demultiplex based on NLRI length per RFC specs
		switch length {
		case 12:
			// RFC 6074 BGP-AD format
			nlri, err = unmarshalRFC6074NLRI(b[p : p+int(length)])
			if err != nil {
				return nil, fmt.Errorf("RFC 6074 NLRI parse error at offset %d: %w", p-2, err)
			}
		case 17:
			// RFC 4761 VPLS-BGP format
			nlri, err = unmarshalRFC4761NLRI(b[p : p+int(length)])
			if err != nil {
				return nil, fmt.Errorf("RFC 4761 NLRI parse error at offset %d: %w", p-2, err)
			}
		default:
			// Unknown NLRI length - not RFC 4761 or RFC 6074
			return nil, fmt.Errorf("unknown VPLS NLRI length: %d at offset %d (expected 12 or 17)", length, p-2)
		}

		nlri.Length = length
		r.Route = append(r.Route, nlri)
		p += int(length)
	}

	return r, nil
}
