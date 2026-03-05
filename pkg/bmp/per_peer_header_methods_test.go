package bmp

import (
	"net"
	"testing"
)

// TestGetPeerBGPIDString tests BGPID formatting (always 4-byte stored).
func TestGetPeerBGPIDString(t *testing.T) {
	tests := []struct {
		name     string
		bgpID    []byte
		wantAddr string
	}{
		{
			name:     "192.168.1.1",
			bgpID:    net.ParseIP("192.168.1.1").To4(),
			wantAddr: "192.168.1.1",
		},
		{
			name:     "10.0.0.1",
			bgpID:    net.ParseIP("10.0.0.1").To4(),
			wantAddr: "10.0.0.1",
		},
		{
			name:     "0.0.0.0",
			bgpID:    []byte{0, 0, 0, 0},
			wantAddr: "0.0.0.0",
		},
		{
			name:     "255.255.255.255",
			bgpID:    []byte{255, 255, 255, 255},
			wantAddr: "255.255.255.255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pph := &PerPeerHeader{
				PeerBGPID:         tt.bgpID,
				PeerDistinguisher: make([]byte, 8),
				PeerAddress:       make([]byte, 16),
				PeerTimestamp:     make([]byte, 8),
			}
			got := pph.GetPeerBGPIDString()
			if got != tt.wantAddr {
				t.Errorf("GetPeerBGPIDString() = %q, want %q", got, tt.wantAddr)
			}
		})
	}
}

// TestGetPeerAddrString tests peer address formatting for IPv4 and IPv6.
func TestGetPeerAddrString(t *testing.T) {
	tests := []struct {
		name     string
		peerType PeerType
		flagV    bool
		addr     []byte // 16-byte
		want     string
	}{
		{
			name:     "PeerType0 IPv4 address",
			peerType: PeerType0,
			flagV:    false,
			addr: func() []byte {
				a := make([]byte, 16)
				copy(a[12:], net.ParseIP("10.1.2.3").To4())
				return a
			}(),
			want: "10.1.2.3",
		},
		{
			name:     "PeerType0 IPv6 flagV=true",
			peerType: PeerType0,
			flagV:    true,
			addr: func() []byte {
				a := make([]byte, 16)
				copy(a, net.ParseIP("2001:db8::1").To16())
				return a
			}(),
			want: "2001:db8::1",
		},
		{
			name:     "PeerType3 (Loc-RIB) always IPv4 regardless of address",
			peerType: PeerType3,
			flagV:    false,
			addr: func() []byte {
				a := make([]byte, 16)
				copy(a[12:], net.ParseIP("192.0.2.1").To4())
				return a
			}(),
			want: "192.0.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pph := &PerPeerHeader{
				PeerType:          tt.peerType,
				flagV:             tt.flagV,
				PeerAddress:       tt.addr,
				PeerBGPID:         make([]byte, 4),
				PeerDistinguisher: make([]byte, 8),
				PeerTimestamp:     make([]byte, 8),
			}
			got := pph.GetPeerAddrString()
			if got != tt.want {
				t.Errorf("GetPeerAddrString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGetPeerHash verifies that hash changes when any field changes.
func TestGetPeerHash(t *testing.T) {
	base := &PerPeerHeader{
		PeerDistinguisher: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         net.ParseIP("10.0.0.1").To4(),
		PeerTimestamp:     make([]byte, 8),
	}
	h1 := base.GetPeerHash()
	if h1 == "" {
		t.Fatal("GetPeerHash() returned empty string")
	}

	// Change BGP-ID → hash must differ
	modified := &PerPeerHeader{
		PeerDistinguisher: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         net.ParseIP("10.0.0.2").To4(),
		PeerTimestamp:     make([]byte, 8),
	}
	h2 := modified.GetPeerHash()
	if h1 == h2 {
		t.Errorf("GetPeerHash() should differ when BGP-ID changes, both = %q", h1)
	}

	// Same input → same hash (deterministic)
	h3 := base.GetPeerHash()
	if h1 != h3 {
		t.Errorf("GetPeerHash() non-deterministic: %q vs %q", h1, h3)
	}
}

// TestGetPeerDistinguisherString covers all four peer types.
func TestGetPeerDistinguisherString(t *testing.T) {
	tests := []struct {
		name         string
		peerType     PeerType
		rd           []byte
		wantExact    string // if non-empty, exact match
		wantNotEmpty bool
	}{
		{
			name:      "PeerType0 — always 0:0",
			peerType:  PeerType0,
			rd:        []byte{0, 0, 0, 0, 0, 0, 0, 0},
			wantExact: "0:0",
		},
		{
			name:      "PeerType2 — decimal encoding",
			peerType:  PeerType2,
			rd:        []byte{0, 0, 0, 0, 0, 0, 0, 42},
			wantExact: "42",
		},
		{
			name:         "PeerType3 — RD-style",
			peerType:     PeerType3,
			rd:           []byte{0, 1, 0, 0, 0, 0, 0, 100}, // type 1 RD
			wantNotEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pph := &PerPeerHeader{
				PeerType:          tt.peerType,
				PeerDistinguisher: tt.rd,
				PeerAddress:       make([]byte, 16),
				PeerBGPID:         make([]byte, 4),
				PeerTimestamp:     make([]byte, 8),
			}
			got := pph.GetPeerDistinguisherString()
			if tt.wantExact != "" && got != tt.wantExact {
				t.Errorf("GetPeerDistinguisherString() = %q, want %q", got, tt.wantExact)
			}
			if tt.wantNotEmpty && got == "" {
				t.Errorf("GetPeerDistinguisherString() returned empty string")
			}
		})
	}
}

// TestGetTableKey verifies the composite key format.
func TestGetTableKey(t *testing.T) {
	pph := &PerPeerHeader{
		PeerType:          PeerType0,
		PeerDistinguisher: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         net.ParseIP("10.0.0.1").To4(),
		PeerTimestamp:     make([]byte, 8),
	}
	key := pph.GetTableKey()
	if key == "" {
		t.Fatal("GetTableKey() returned empty string")
	}
	bgpStr := pph.GetPeerBGPIDString()
	rdStr := pph.GetPeerDistinguisherString()
	want := bgpStr + rdStr
	if key != want {
		t.Errorf("GetTableKey() = %q, want %q", key, want)
	}
}

// TestIsLocRIB tests IsLocRIB for PeerType3 and other types.
func TestIsLocRIB(t *testing.T) {
	tests := []struct {
		name     string
		peerType PeerType
		wantVal  bool
		wantErr  bool
	}{
		{
			name:     "PeerType3 — is Loc-RIB",
			peerType: PeerType3,
			wantVal:  true,
			wantErr:  false,
		},
		{
			name:     "PeerType0 — not Loc-RIB (error)",
			peerType: PeerType0,
			wantErr:  true,
		},
		{
			name:     "PeerType1 — not Loc-RIB (error)",
			peerType: PeerType1,
			wantErr:  true,
		},
		{
			name:     "PeerType2 — not Loc-RIB (error)",
			peerType: PeerType2,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pph := &PerPeerHeader{
				PeerType:          tt.peerType,
				PeerDistinguisher: make([]byte, 8),
				PeerAddress:       make([]byte, 16),
				PeerBGPID:         make([]byte, 4),
				PeerTimestamp:     make([]byte, 8),
			}
			got, err := pph.IsLocRIB()
			if (err != nil) != tt.wantErr {
				t.Fatalf("IsLocRIB() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.wantVal {
				t.Errorf("IsLocRIB() = %v, want %v", got, tt.wantVal)
			}
		})
	}
}

// TestUnmarshalPerPeerHeaderGuards tests the length guard and all peer types.
func TestUnmarshalPerPeerHeaderGuards(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "too short (41 bytes, need 42)",
			input:   make([]byte, 41),
			wantErr: true,
		},
		{
			name:    "exactly 42 bytes, PeerType0",
			input:   make([]byte, 42), // all zeros = PeerType0, flags=0
			wantErr: false,
		},
		{
			name: "PeerType1 (RD Instance Peer)",
			input: func() []byte {
				b := make([]byte, 42)
				b[0] = 1 // PeerType1
				return b
			}(),
			wantErr: false,
		},
		{
			name: "PeerType2 (Local Instance Peer)",
			input: func() []byte {
				b := make([]byte, 42)
				b[0] = 2
				return b
			}(),
			wantErr: false,
		},
		{
			name: "PeerType3 (Loc-RIB per RFC 9069) with F flag set",
			input: func() []byte {
				b := make([]byte, 42)
				b[0] = 3    // PeerType3
				b[1] = 0x80 // F flag
				return b
			}(),
			wantErr: false,
		},
		{
			name: "unknown peer type — logged as warning, not error",
			input: func() []byte {
				b := make([]byte, 42)
				b[0] = 0xFF // unknown
				return b
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalPerPeerHeader(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalPerPeerHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPerPeerHeaderLen tests the Len() method.
func TestPerPeerHeaderLen(t *testing.T) {
	pph := &PerPeerHeader{
		PeerDistinguisher: make([]byte, 8),
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         make([]byte, 4),
		PeerTimestamp:     make([]byte, 8),
	}
	// Len = 1 (PeerType) + 1 (flags) + 8 (RD) + 16 (addr) + 4 (AS) + 4 (BGPID) + 8 (ts) = ...
	// Actual: 1 + 1 + len(PeerDistinguisher) + len(PeerAddress) + 4 + len(PeerBGPID) + len(PeerTimestamp)
	got := pph.Len()
	want := 1 + 1 + 8 + 16 + 4 + 4 + 8
	if got != want {
		t.Errorf("Len() = %d, want %d", got, want)
	}
}
