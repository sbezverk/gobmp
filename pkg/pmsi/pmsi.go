package pmsi

import (
	"fmt"
)

// TunnelType defines PMSI tunnel types per RFC 6514 Section 4
type TunnelType uint8

const (
	// TunnelTypeNoTunnel indicates no tunnel information present (RFC 6514)
	TunnelTypeNoTunnel TunnelType = 0
	// TunnelTypeRSVPTE indicates RSVP-TE P2MP LSP (RFC 6514)
	TunnelTypeRSVPTE TunnelType = 1
	// TunnelTypeMLDP indicates mLDP P2MP LSP (RFC 6514)
	TunnelTypeMLDP TunnelType = 2
	// TunnelTypePIM indicates PIM-SSM Tree (RFC 6514)
	TunnelTypePIM TunnelType = 3
	// TunnelTypePIMBidir indicates PIM-SM Tree (bidirectional) (RFC 6514)
	TunnelTypePIMBidir TunnelType = 4
	// TunnelTypePIMSM indicates PIM-SM Tree (sparse mode) (RFC 6514)
	TunnelTypePIMSM TunnelType = 5
	// TunnelTypeBIER indicates BIIER (RFC 6514)
	TunnelTypeBIER TunnelType = 6
	// TunnelTypeIngressRepl indicates Ingress Replication (RFC 6514)
	TunnelTypeIngressRepl TunnelType = 7
	// TunnelTypeMLDPMP2MP indicates mLDP MP2MP LSP (RFC 6514)
	TunnelTypeMLDPMP2MP TunnelType = 8
)

// PMSITunnel represents RFC 6514 PMSI Tunnel Attribute for EVPN Type 3
// Format: Flags (1 byte) + Tunnel Type (1 byte) + MPLS Label (3 bytes, optional) + Tunnel Identifier (variable)
type PMSITunnel struct {
	Flags            uint8      `json:"flags"`
	TunnelType       TunnelType `json:"tunnel_type"`
	MPLSLabel        *uint32    `json:"mpls_label,omitempty"`        // 20-bit label, nil if L bit not set
	TunnelIdentifier []byte     `json:"tunnel_identifier,omitempty"` // Variable length, type-specific
}

// ParsePMSITunnel parses PMSI Tunnel Attribute from raw bytes (RFC 6514 Section 4)
func ParsePMSITunnel(data []byte) (*PMSITunnel, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("PMSI tunnel data too short: %d bytes, expected at least 2", len(data))
	}

	tunnel := &PMSITunnel{
		Flags:      data[0],
		TunnelType: TunnelType(data[1]),
	}

	offset := 2

	// Check L bit (bit 0 in Flags) to determine if MPLS Label is present
	if tunnel.Flags&0x01 != 0 {
		if len(data) < 5 {
			return nil, fmt.Errorf("PMSI tunnel missing MPLS label: data length %d, expected at least 5", len(data))
		}
		// Parse 20-bit MPLS label from 3 bytes (RFC 6514 Section 5)
		// Label occupies upper 20 bits, followed by 3-bit EXP and 1-bit S
		label := uint32(data[2])<<12 | uint32(data[3])<<4 | uint32(data[4])>>4
		tunnel.MPLSLabel = &label
		offset = 5
	}

	// Rest is tunnel identifier (format depends on tunnel type)
	if offset < len(data) {
		tunnel.TunnelIdentifier = data[offset:]
	}

	return tunnel, nil
}
