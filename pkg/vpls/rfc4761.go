package vpls

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
)

// unmarshalRFC4761NLRI parses RFC 4761 VPLS-BGP NLRI (17 bytes)
//
// RFC 4761 NLRI Format:
//
//	+------------------------------------+
//	|  Length (2 octets)                 | <-- handled by caller
//	+------------------------------------+
//	|  Route Distinguisher (8 octets)    | offset 0-7
//	+------------------------------------+
//	|  VE ID (2 octets)                  | offset 8-9
//	+------------------------------------+
//	|  VE Block Offset (2 octets)        | offset 10-11
//	+------------------------------------+
//	|  VE Block Size (2 octets)          | offset 12-13
//	+------------------------------------+
//	|  Label Base (3 octets)             | offset 14-16
//	+------------------------------------+
func unmarshalRFC4761NLRI(b []byte) (*NLRI, error) {
	// RFC 4761 Section 3.2.2: NLRI must be exactly 17 bytes
	if len(b) != 17 {
		return nil, fmt.Errorf("RFC 4761 NLRI must be 17 bytes, got %d", len(b))
	}

	nlri := &NLRI{
		RFCType: "RFC4761",
	}

	// Parse Route Distinguisher (8 bytes, offset 0-7)
	rd, err := base.MakeRD(b[0:8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Route Distinguisher: %w", err)
	}
	nlri.RD = rd

	// Parse VE ID (2 bytes, offset 8-9)
	veID := binary.BigEndian.Uint16(b[8:10])
	nlri.VEID = &veID

	// Parse VE Block Offset (2 bytes, offset 10-11)
	veBlockOffset := binary.BigEndian.Uint16(b[10:12])
	nlri.VEBlockOffset = &veBlockOffset

	// Parse VE Block Size (2 bytes, offset 12-13)
	veBlockSize := binary.BigEndian.Uint16(b[12:14])
	nlri.VEBlockSize = &veBlockSize

	// Parse Label Base (3 bytes, offset 14-16)
	// RFC 4761 Section 3.2.2: Label Base is a 20-bit MPLS label
	// Format: [Label (20 bits)][TC (3 bits)][S (1 bit)][TTL (8 bits)]
	// We extract the 20-bit label value
	labelBase := uint32(b[14])<<12 | uint32(b[15])<<4 | uint32(b[16])>>4

	// Validate label is within 20-bit range (0 - 1,048,575)
	if labelBase > 0xFFFFF {
		return nil, fmt.Errorf("label base 0x%x exceeds 20-bit MPLS label range (max 0xFFFFF)", labelBase)
	}

	nlri.LabelBase = &labelBase

	return nlri, nil
}

// GetPEAddress returns the PE router address for RFC 4761 NLRI
// For RFC 4761, PE address comes from BGP Next Hop, not NLRI
func (n *NLRI) GetPEAddress() string {
	if n.RFCType == "RFC6074" && n.PEAddr != nil {
		return *n.PEAddr
	}
	// RFC 4761 doesn't include PE address in NLRI
	return ""
}

// GetLabelRange calculates the label block range for RFC 4761
// Returns (labelStart, labelEnd) or (0, 0) if not RFC 4761
func (n *NLRI) GetLabelRange() (uint32, uint32) {
	if n.RFCType != "RFC4761" || n.LabelBase == nil || n.VEBlockSize == nil {
		return 0, 0
	}

	labelStart := *n.LabelBase
	labelEnd := labelStart + uint32(*n.VEBlockSize) - 1

	return labelStart, labelEnd
}

// String returns a human-readable representation of the NLRI
func (n *NLRI) String() string {
	if n.RFCType == "RFC4761" {
		labelStart, labelEnd := n.GetLabelRange()
		return fmt.Sprintf("VPLS RFC4761 RD=%s VEID=%d BlockOffset=%d BlockSize=%d Labels=%d-%d",
			n.RD.String(),
			*n.VEID,
			*n.VEBlockOffset,
			*n.VEBlockSize,
			labelStart,
			labelEnd,
		)
	}
	return fmt.Sprintf("VPLS %s RD=%s", n.RFCType, n.RD.String())
}

// Helper function to format IPv4 address from 4-byte slice
func formatIPv4(b []byte) (string, error) {
	if len(b) != 4 {
		return "", fmt.Errorf("IPv4 address must be 4 bytes, got %d", len(b))
	}
	return net.IP(b).String(), nil
}
