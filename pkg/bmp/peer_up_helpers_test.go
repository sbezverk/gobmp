package bmp

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestPeerUpMessageHelpers tests GetLocalAddressString, GetVRFTableName,
// and GetAdminLabel on PeerUpMessage.
func TestPeerUpMessageHelpers(t *testing.T) {
	t.Run("GetLocalAddressString IPv4 peer", func(t *testing.T) {
		addr := make([]byte, 16)
		copy(addr[12:], net.ParseIP("192.168.10.1").To4())
		pum := &PeerUpMessage{
			LocalAddress:     addr,
			isRemotePeerIPv6: false,
		}
		got := pum.GetLocalAddressString()
		if got != "192.168.10.1" {
			t.Errorf("GetLocalAddressString() = %q, want 192.168.10.1", got)
		}
	})

	t.Run("GetLocalAddressString IPv6 peer", func(t *testing.T) {
		addr := net.ParseIP("2001:db8::cafe").To16()
		pum := &PeerUpMessage{
			LocalAddress:     addr,
			isRemotePeerIPv6: true,
		}
		got := pum.GetLocalAddressString()
		want := net.ParseIP("2001:db8::cafe").To16().String()
		if got != want {
			t.Errorf("GetLocalAddressString() = %q, want %q", got, want)
		}
	})

	t.Run("GetVRFTableName present (TLV type=3)", func(t *testing.T) {
		pum := &PeerUpMessage{
			Information: []InformationalTLV{
				{InformationType: 3, InformationLength: 5, Information: []byte("vrf10")},
			},
		}
		name, ok := pum.GetVRFTableName()
		if !ok {
			t.Fatal("GetVRFTableName() ok = false, want true")
		}
		if name != "vrf10" {
			t.Errorf("GetVRFTableName() = %q, want %q", name, "vrf10")
		}
	})

	t.Run("GetVRFTableName absent", func(t *testing.T) {
		pum := &PeerUpMessage{
			Information: []InformationalTLV{
				{InformationType: 0, InformationLength: 3, Information: []byte("foo")},
			},
		}
		_, ok := pum.GetVRFTableName()
		if ok {
			t.Error("GetVRFTableName() ok = true, want false when TLV type=3 absent")
		}
	})

	t.Run("GetVRFTableName empty Information slice", func(t *testing.T) {
		pum := &PeerUpMessage{Information: []InformationalTLV{}}
		_, ok := pum.GetVRFTableName()
		if ok {
			t.Error("GetVRFTableName() ok = true, want false for empty Information")
		}
	})

	t.Run("GetAdminLabel present (TLV type=4)", func(t *testing.T) {
		pum := &PeerUpMessage{
			Information: []InformationalTLV{
				{InformationType: 4, InformationLength: 8, Information: []byte("dc1-spine")},
			},
		}
		label, ok := pum.GetAdminLabel()
		if !ok {
			t.Fatal("GetAdminLabel() ok = false, want true")
		}
		if label != "dc1-spine" {
			t.Errorf("GetAdminLabel() = %q, want %q", label, "dc1-spine")
		}
	})

	t.Run("GetAdminLabel absent", func(t *testing.T) {
		pum := &PeerUpMessage{
			Information: []InformationalTLV{
				{InformationType: 3, InformationLength: 5, Information: []byte("vrf10")},
			},
		}
		_, ok := pum.GetAdminLabel()
		if ok {
			t.Error("GetAdminLabel() ok = true, want false when TLV type=4 absent")
		}
	})

	t.Run("GetVRFTableName and GetAdminLabel both present", func(t *testing.T) {
		pum := &PeerUpMessage{
			Information: []InformationalTLV{
				{InformationType: 0, InformationLength: 4, Information: []byte("note")},
				{InformationType: 3, InformationLength: 6, Information: []byte("vrf100")},
				{InformationType: 4, InformationLength: 5, Information: []byte("label")},
			},
		}
		name, ok := pum.GetVRFTableName()
		if !ok || name != "vrf100" {
			t.Errorf("GetVRFTableName() = (%q, %v), want (vrf100, true)", name, ok)
		}
		lbl, ok := pum.GetAdminLabel()
		if !ok || lbl != "label" {
			t.Errorf("GetAdminLabel() = (%q, %v), want (label, true)", lbl, ok)
		}
	})
}

// TestUnmarshalPeerUpMessageGuards tests length guards in the parser.
func TestUnmarshalPeerUpMessageGuards(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		isIPv6  bool
		wantErr bool
	}{
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "too short (15 bytes — LocalAddress needs 16)",
			input:   make([]byte, 15),
			wantErr: true,
		},
		{
			name:    "16 bytes — missing LocalPort",
			input:   make([]byte, 16),
			wantErr: true,
		},
		{
			name:    "18 bytes — missing RemotePort",
			input:   make([]byte, 18),
			wantErr: true,
		},
		{
			name: "20 bytes — missing first BGP marker",
			// LocalAddr(16) + LocalPort(2) + RemotePort(2) = 20 bytes, no marker
			input:   make([]byte, 20),
			wantErr: true,
		},
		{
			// Enough bytes through the first BGP marker but length field 0 → too small
			name: "first marker present but BGP length=0 (too short)",
			input: func() []byte {
				b := make([]byte, 16+2+2+16+2)
				// LocalAddress: 16 zeros
				// LocalPort, RemotePort: 0
				// First BGP marker: 16 bytes of 0xFF
				for i := 16 + 2 + 2; i < 16+2+2+16; i++ {
					b[i] = 0xFF
				}
				// length=0 → will fail "less than minimum 16 bytes" check
				binary.BigEndian.PutUint16(b[16+2+2+16:], 0)
				return b
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalPeerUpMessage(tt.input, tt.isIPv6)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalPeerUpMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
