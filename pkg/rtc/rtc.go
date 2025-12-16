// Package rtc implements parsers for Route Target Constraint (RTC) NLRI per RFC 4684.
//
// RFC 4684 defines Route Target Constraint for optimizing VPN route distribution.
// The NLRI format is [Origin AS, Route Target] carried in AFI 1/2, SAFI 132.
//
// Wire format:
//
//	+-------------------------------+
//	| Length (1 byte, in bits)      |
//	+-------------------------------+
//	| Origin AS (4 octets)          |
//	+-------------------------------+
//	| Route Target (8 octets)       |
//	+   Extended Community          +
//	|                               |
//	+-------------------------------+
//
// Length can be 0-96 bits to support wildcard matching:
//   - 0 bits: wildcard (match all RTs)
//   - 32 bits: Origin AS only
//   - 96 bits: Full Origin AS + Route Target
package rtc

import (
	"encoding/binary"
	"fmt"
)

// Route defines a collection of RTC NLRI objects
type Route struct {
	NLRI []*NLRI
}

// NLRI represents a single Route Target Constraint NLRI per RFC 4684
type NLRI struct {
	Length      uint8  // Length in bits (0-96)
	OriginAS    uint32 // Autonomous System of NLRI originator
	RouteTarget []byte // 8-byte Extended Community (Type 0x00/0x01/0x02, SubType 0x02)
}

// UnmarshalRTCNLRI parses RTC NLRI from wire format per RFC 4684 Section 4
func UnmarshalRTCNLRI(b []byte) (*Route, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}

	r := &Route{
		NLRI: make([]*NLRI, 0),
	}

	for p := 0; p < len(b); {
		// Check minimum length for length field
		if p+1 > len(b) {
			return nil, fmt.Errorf("incomplete NLRI at offset %d: need 1 byte for length, have %d", p, len(b)-p)
		}

		nlri := &NLRI{}

		// Parse length field (in bits)
		nlri.Length = b[p]
		p++

		// RFC 4684: length can be 0 (wildcard), 32 (AS only), or 96 (AS + RT)
		// Validate length before checking available bytes
		if nlri.Length != 0 && nlri.Length != 32 && nlri.Length != 96 {
			return nil, fmt.Errorf("invalid NLRI length %d bits (valid: 0, 32, or 96)", nlri.Length)
		}

		// Parse Origin AS (4 bytes) if length >= 32 bits
		if nlri.Length >= 32 {
			if p+4 > len(b) {
				return nil, fmt.Errorf("incomplete Origin AS at offset %d", p)
			}
			nlri.OriginAS = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}

		// Parse Route Target Extended Community (8 bytes) if length == 96 bits
		if nlri.Length == 96 {
			if p+8 > len(b) {
				return nil, fmt.Errorf("incomplete Route Target at offset %d", p)
			}

			// Validate Route Target Extended Community
			if err := validateRouteTarget(b[p : p+8]); err != nil {
				return nil, fmt.Errorf("invalid Route Target at offset %d: %w", p, err)
			}

			// Store raw 8 bytes
			nlri.RouteTarget = make([]byte, 8)
			copy(nlri.RouteTarget, b[p:p+8])
			p += 8
		}

		r.NLRI = append(r.NLRI, nlri)
	}

	return r, nil
}

// validateRouteTarget validates an 8-byte Route Target Extended Community
// Route Target must be Type 0x00, 0x01, or 0x02 with SubType 0x02
func validateRouteTarget(b []byte) error {
	if len(b) != 8 {
		return fmt.Errorf("invalid Route Target length: expected 8 bytes, got %d", len(b))
	}

	extType := b[0]
	extSubType := b[1]

	// Validate type (must be transitive 2-byte AS, IPv4, or 4-byte AS)
	typeBase := extType & 0x3f
	if typeBase != 0x00 && typeBase != 0x01 && typeBase != 0x02 {
		return fmt.Errorf("unsupported Route Target type 0x%02x (expected 0x00, 0x01, or 0x02)", extType)
	}

	// Validate SubType (must be 0x02 for Route Target per RFC 4360)
	if extSubType != 0x02 {
		return fmt.Errorf("invalid SubType 0x%02x (Route Target requires SubType 0x02)", extSubType)
	}

	return nil
}

// String returns human-readable representation of RTC NLRI
func (n *NLRI) String() string {
	if n.Length == 0 {
		return "RTC{wildcard}"
	}
	if n.Length == 32 {
		return fmt.Sprintf("RTC{AS=%d}", n.OriginAS)
	}
	if n.RouteTarget != nil && len(n.RouteTarget) == 8 {
		// Format Route Target based on type
		rtType := n.RouteTarget[0] & 0x3f
		switch rtType {
		case 0x00: // 2-byte AS
			as := binary.BigEndian.Uint16(n.RouteTarget[2:4])
			val := binary.BigEndian.Uint32(n.RouteTarget[4:8])
			return fmt.Sprintf("RTC{AS=%d, RT=%d:%d}", n.OriginAS, as, val)
		case 0x01: // IPv4
			ip := fmt.Sprintf("%d.%d.%d.%d", n.RouteTarget[2], n.RouteTarget[3], n.RouteTarget[4], n.RouteTarget[5])
			val := binary.BigEndian.Uint16(n.RouteTarget[6:8])
			return fmt.Sprintf("RTC{AS=%d, RT=%s:%d}", n.OriginAS, ip, val)
		case 0x02: // 4-byte AS
			as := binary.BigEndian.Uint32(n.RouteTarget[2:6])
			val := binary.BigEndian.Uint16(n.RouteTarget[6:8])
			return fmt.Sprintf("RTC{AS=%d, RT=%d:%d}", n.OriginAS, as, val)
		default:
			return fmt.Sprintf("RTC{AS=%d, RT=0x%x}", n.OriginAS, n.RouteTarget)
		}
	}
	return fmt.Sprintf("RTC{length=%d, AS=%d}", n.Length, n.OriginAS)
}
