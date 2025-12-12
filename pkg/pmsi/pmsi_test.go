package pmsi

import (
	"testing"
)

// TestParsePMSITunnel_NoLabel tests PMSI tunnel without MPLS label (L bit = 0)
func TestParsePMSITunnel_NoLabel(t *testing.T) {
	// Flags=0x00 (L bit not set), TunnelType=7 (Ingress Replication), TunnelID=4 bytes
	data := []byte{0x00, 0x07, 0x0A, 0x00, 0x00, 0x01}

	tunnel, err := ParsePMSITunnel(data)
	if err != nil {
		t.Fatalf("ParsePMSITunnel() error = %v", err)
	}

	if tunnel.Flags != 0x00 {
		t.Errorf("Flags = %d, want 0", tunnel.Flags)
	}
	if tunnel.TunnelType != TunnelTypeIngressRepl {
		t.Errorf("TunnelType = %d, want %d", tunnel.TunnelType, TunnelTypeIngressRepl)
	}
	if tunnel.MPLSLabel != nil {
		t.Errorf("MPLSLabel should be nil when L bit not set")
	}
	if len(tunnel.TunnelIdentifier) != 4 {
		t.Errorf("TunnelIdentifier length = %d, want 4", len(tunnel.TunnelIdentifier))
	}
}

// TestParsePMSITunnel_WithLabel tests PMSI tunnel with MPLS label (L bit = 1)
func TestParsePMSITunnel_WithLabel(t *testing.T) {
	// Flags=0x01 (L bit set), TunnelType=1 (RSVP-TE), MPLS Label=12345, TunnelID=4 bytes
	data := make([]byte, 9)
	data[0] = 0x01 // Flags with L bit set
	data[1] = 0x01 // TunnelType = RSVP-TE

	// MPLS label 12345: encoded as (12345 << 12) in the first 20 bits of 3 bytes
	// The parser prepends a 0 byte and reads as uint32, then shifts right by 12
	// So we need the 3 bytes to be [0x30, 0x39, 0x00] (from 0x3039000)
	data[2] = 0x30
	data[3] = 0x39
	data[4] = 0x00

	// Tunnel ID
	copy(data[5:], []byte{0x01, 0x02, 0x03, 0x04})

	tunnel, err := ParsePMSITunnel(data)
	if err != nil {
		t.Fatalf("ParsePMSITunnel() error = %v", err)
	}

	if tunnel.Flags != 0x01 {
		t.Errorf("Flags = %d, want 1", tunnel.Flags)
	}
	if tunnel.TunnelType != TunnelTypeRSVPTE {
		t.Errorf("TunnelType = %d, want %d", tunnel.TunnelType, TunnelTypeRSVPTE)
	}
	if tunnel.MPLSLabel == nil {
		t.Fatal("MPLSLabel should not be nil when L bit is set")
	}
	if *tunnel.MPLSLabel != 12345 {
		t.Errorf("MPLSLabel = %d, want 12345", *tunnel.MPLSLabel)
	}
	if len(tunnel.TunnelIdentifier) != 4 {
		t.Errorf("TunnelIdentifier length = %d, want 4", len(tunnel.TunnelIdentifier))
	}
}

// TestParsePMSITunnel_AllTunnelTypes tests all RFC 6514 tunnel types
func TestParsePMSITunnel_AllTunnelTypes(t *testing.T) {
	types := []struct {
		name       string
		tunnelType TunnelType
	}{
		{"NoTunnel", TunnelTypeNoTunnel},
		{"RSVP-TE", TunnelTypeRSVPTE},
		{"mLDP", TunnelTypeMLDP},
		{"PIM-SSM", TunnelTypePIM},
		{"PIM-Bidir", TunnelTypePIMBidir},
		{"PIM-SM", TunnelTypePIMSM},
		{"BIER", TunnelTypeBIER},
		{"IngressRepl", TunnelTypeIngressRepl},
		{"mLDP-MP2MP", TunnelTypeMLDPMP2MP},
	}

	for _, tt := range types {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte{0x00, uint8(tt.tunnelType), 0x00, 0x00}

			tunnel, err := ParsePMSITunnel(data)
			if err != nil {
				t.Fatalf("ParsePMSITunnel() error = %v", err)
			}

			if tunnel.TunnelType != tt.tunnelType {
				t.Errorf("TunnelType = %d, want %d", tunnel.TunnelType, tt.tunnelType)
			}
		})
	}
}

// TestParsePMSITunnel_TooShort tests error handling for truncated data
func TestParsePMSITunnel_TooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"Empty", []byte{}},
		{"OneByte", []byte{0x01}},
		{"LabelMissing", []byte{0x01, 0x07}}, // L bit set but no label
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePMSITunnel(tt.data)
			if err == nil {
				t.Error("ParsePMSITunnel() expected error for truncated data, got nil")
			}
		})
	}
}

// TestParsePMSITunnel_EmptyTunnelID tests PMSI with no tunnel identifier
func TestParsePMSITunnel_EmptyTunnelID(t *testing.T) {
	// Flags=0x00, TunnelType=0 (no tunnel)
	data := []byte{0x00, 0x00}

	tunnel, err := ParsePMSITunnel(data)
	if err != nil {
		t.Fatalf("ParsePMSITunnel() error = %v", err)
	}

	if len(tunnel.TunnelIdentifier) != 0 {
		t.Errorf("TunnelIdentifier should be empty, got %d bytes", len(tunnel.TunnelIdentifier))
	}
}

// TestParsePMSITunnel_LargeTunnelID tests PMSI with large tunnel identifier
func TestParsePMSITunnel_LargeTunnelID(t *testing.T) {
	// Create data with large tunnel identifier
	tunnelID := make([]byte, 100)
	for i := range tunnelID {
		tunnelID[i] = byte(i)
	}

	data := append([]byte{0x00, 0x02}, tunnelID...) // Type=mLDP

	tunnel, err := ParsePMSITunnel(data)
	if err != nil {
		t.Fatalf("ParsePMSITunnel() error = %v", err)
	}

	if len(tunnel.TunnelIdentifier) != 100 {
		t.Errorf("TunnelIdentifier length = %d, want 100", len(tunnel.TunnelIdentifier))
	}

	for i := 0; i < 100; i++ {
		if tunnel.TunnelIdentifier[i] != byte(i) {
			t.Errorf("TunnelIdentifier[%d] = %d, want %d", i, tunnel.TunnelIdentifier[i], i)
		}
	}
}

// TestParsePMSITunnel_RFC6514_Example tests parsing of RFC 6514 example
func TestParsePMSITunnel_RFC6514_Example(t *testing.T) {
	// Simulate RFC 6514 Ingress Replication example
	// Flags=0x01 (L bit set), Type=7, Label=1000, TunnelID=192.0.2.1 (4 bytes)
	data := make([]byte, 9)
	data[0] = 0x01 // L bit set
	data[1] = 0x07 // Ingress Replication

	// MPLS label 1000
	label := uint32(1000) << 12
	data[2] = byte(label >> 16)
	data[3] = byte(label >> 8)
	data[4] = byte(label)

	// Tunnel ID = 192.0.2.1
	data[5] = 192
	data[6] = 0
	data[7] = 2
	data[8] = 1

	tunnel, err := ParsePMSITunnel(data)
	if err != nil {
		t.Fatalf("ParsePMSITunnel() error = %v", err)
	}

	if tunnel.Flags&0x01 == 0 {
		t.Error("L bit should be set")
	}
	if tunnel.TunnelType != TunnelTypeIngressRepl {
		t.Errorf("TunnelType = %d, want %d", tunnel.TunnelType, TunnelTypeIngressRepl)
	}
	if tunnel.MPLSLabel == nil || *tunnel.MPLSLabel != 1000 {
		t.Errorf("MPLSLabel = %v, want 1000", tunnel.MPLSLabel)
	}
	if len(tunnel.TunnelIdentifier) != 4 {
		t.Errorf("TunnelIdentifier length = %d, want 4", len(tunnel.TunnelIdentifier))
	}
}
