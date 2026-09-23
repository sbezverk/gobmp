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
// Format: Flags (1 byte) + Tunnel Type (1 byte) + MPLS Label (3 bytes) + Tunnel Identifier (variable)
type PMSITunnel struct {
	Flags      uint8      `json:"flags"`
	TunnelType TunnelType `json:"tunnel_type"`
	// MPLSLabel is the 20-bit label value (RFC 6514 S5). The Leaf Information
	// Required flag (bit 0 of Flags) governs whether a receiver must respond
	// with Leaf A-D routes, not whether the label field is present - RFC 6514
	// fixes this attribute's layout regardless of flags.
	MPLSLabel *uint32 `json:"mpls_label,omitempty"`
	// RawLabel is the label's raw 24-bit value, unshifted. For a VXLAN tunnel
	// this is the VNI (RFC 8365 S5.1.3), the same raw/shifted relationship
	// EVPNPrefix.RawLabels/Labels already carries for route types 2 and 5.
	RawLabel         uint32 `json:"raw_label"`
	TunnelIdentifier []byte `json:"tunnel_identifier,omitempty"` // Variable length, type-specific
}

// ParsePMSITunnel parses PMSI Tunnel Attribute from raw bytes (RFC 6514 Section 4)
func ParsePMSITunnel(data []byte) (*PMSITunnel, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("PMSI tunnel data too short: %d bytes, expected at least 5 (flags+type+label)", len(data))
	}

	tunnel := &PMSITunnel{
		Flags:      data[0],
		TunnelType: TunnelType(data[1]),
	}

	// Label occupies upper 20 bits of the 3-byte field, followed by 3-bit EXP
	// and 1-bit S (RFC 6514 S5) - same encoding as base.MakeLabel.
	tunnel.RawLabel = uint32(data[2])<<16 | uint32(data[3])<<8 | uint32(data[4])
	label := uint32(data[2])<<12 | uint32(data[3])<<4 | uint32(data[4])>>4
	tunnel.MPLSLabel = &label

	if len(data) > 5 {
		tunnel.TunnelIdentifier = data[5:]
	}

	return tunnel, nil
}
