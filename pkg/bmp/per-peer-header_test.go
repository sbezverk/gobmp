package bmp

import (
	"testing"
)

// TestPerPeerHeaderFlags tests the interpretation of all flags per RFC 7854, RFC 8671, RFC 9069
func TestPerPeerHeaderFlags(t *testing.T) {
	tests := []struct {
		name              string
		flagsByte         byte
		peerType          uint8
		expectIPv6        bool
		expect4ByteASN    bool
		expectAdjRIBIn    bool
		expectAdjRIBOut   bool
		expectPrePolicy   bool
		expectPostPolicy  bool
		expectRIBInPre    bool
		expectRIBInPost   bool
		expectRIBOutPre   bool
		expectRIBOutPost  bool
	}{
		{
			name:              "RFC 7854: Adj-RIB-In Pre-Policy, IPv4, 2-byte AS (V=0, L=0, A=0, O=0)",
			flagsByte:         0x00, // 0000 0000
			peerType:          0,
			expectIPv6:        false,
			expect4ByteASN:    false,
			expectAdjRIBIn:    true,
			expectAdjRIBOut:   false,
			expectPrePolicy:   true,
			expectPostPolicy:  false,
			expectRIBInPre:    true,
			expectRIBInPost:   false,
			expectRIBOutPre:   false,
			expectRIBOutPost:  false,
		},
		{
			name:              "RFC 8671: Adj-RIB-Out Pre-Policy, IPv4, 2-byte AS (V=0, L=0, A=0, O=1)",
			flagsByte:         0x10, // 0001 0000
			peerType:          0,
			expectIPv6:        false,
			expect4ByteASN:    false,
			expectAdjRIBIn:    false,
			expectAdjRIBOut:   true,
			expectPrePolicy:   true,
			expectPostPolicy:  false,
			expectRIBInPre:    false,
			expectRIBInPost:   false,
			expectRIBOutPre:   true,
			expectRIBOutPost:  false,
		},
		{
			name:              "RFC 7854: Adj-RIB-In Post-Policy, IPv4, 2-byte AS (V=0, L=1, A=0, O=0)",
			flagsByte:         0x40, // 0100 0000
			peerType:          0,
			expectIPv6:        false,
			expect4ByteASN:    false,
			expectAdjRIBIn:    true,
			expectAdjRIBOut:   false,
			expectPrePolicy:   false,
			expectPostPolicy:  true,
			expectRIBInPre:    false,
			expectRIBInPost:   true,
			expectRIBOutPre:   false,
			expectRIBOutPost:  false,
		},
		{
			name:              "RFC 8671: Adj-RIB-Out Post-Policy, IPv4, 2-byte AS (V=0, L=1, A=0, O=1) - ORIGINAL ISSUE",
			flagsByte:         0x50, // 0101 0000
			peerType:          0,
			expectIPv6:        false,
			expect4ByteASN:    false,
			expectAdjRIBIn:    false,
			expectAdjRIBOut:   true,
			expectPrePolicy:   false,
			expectPostPolicy:  true,
			expectRIBInPre:    false,
			expectRIBInPost:   false,
			expectRIBOutPre:   false,
			expectRIBOutPost:  true,
		},
		{
			name:              "RFC 7854: IPv6 peer, 4-byte AS, Adj-RIB-In Pre-Policy (V=1, L=0, A=1, O=0)",
			flagsByte:         0xA0, // 1010 0000
			peerType:          0,
			expectIPv6:        true,
			expect4ByteASN:    true,
			expectAdjRIBIn:    true,
			expectAdjRIBOut:   false,
			expectPrePolicy:   true,
			expectPostPolicy:  false,
			expectRIBInPre:    true,
			expectRIBInPost:   false,
			expectRIBOutPre:   false,
			expectRIBOutPost:  false,
		},
		{
			name:              "RFC 8671: IPv6 peer, 4-byte AS, Adj-RIB-Out Post-Policy (V=1, L=1, A=1, O=1)",
			flagsByte:         0xF0, // 1111 0000
			peerType:          0,
			expectIPv6:        true,
			expect4ByteASN:    true,
			expectAdjRIBIn:    false,
			expectAdjRIBOut:   true,
			expectPrePolicy:   false,
			expectPostPolicy:  true,
			expectRIBInPre:    false,
			expectRIBInPost:   false,
			expectRIBOutPre:   false,
			expectRIBOutPost:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal Per-Peer Header with the flags byte
			pph := &PerPeerHeader{
				PeerType:          PeerType(tt.peerType),
				flagV:             tt.flagsByte&0x80 == 0x80,
				flagL:             tt.flagsByte&0x40 == 0x40,
				flagA:             tt.flagsByte&0x20 == 0x20,
				flagO:             tt.flagsByte&0x10 == 0x10,
				PeerDistinguisher: make([]byte, 8),
				PeerAddress:       make([]byte, 16),
				PeerBGPID:         make([]byte, 4),
				PeerTimestamp:     make([]byte, 8),
			}

			// Test IsRemotePeerIPv6 (no error returned)
			if got := pph.IsRemotePeerIPv6(); got != tt.expectIPv6 {
				t.Errorf("IsRemotePeerIPv6() = %v, want %v", got, tt.expectIPv6)
			}

			// Test Is4ByteASN
			got4Byte, err := pph.Is4ByteASN()
			if err != nil {
				t.Errorf("Is4ByteASN() unexpected error: %v", err)
			}
			if got4Byte != tt.expect4ByteASN {
				t.Errorf("Is4ByteASN() = %v, want %v", got4Byte, tt.expect4ByteASN)
			}

			// Test IsAdjRIBIn
			gotRIBIn, err := pph.IsAdjRIBIn()
			if err != nil {
				t.Errorf("IsAdjRIBIn() unexpected error: %v", err)
			}
			if gotRIBIn != tt.expectAdjRIBIn {
				t.Errorf("IsAdjRIBIn() = %v, want %v", gotRIBIn, tt.expectAdjRIBIn)
			}

			// Test IsAdjRIBOut
			gotRIBOut, err := pph.IsAdjRIBOut()
			if err != nil {
				t.Errorf("IsAdjRIBOut() unexpected error: %v", err)
			}
			if gotRIBOut != tt.expectAdjRIBOut {
				t.Errorf("IsAdjRIBOut() = %v, want %v", gotRIBOut, tt.expectAdjRIBOut)
			}

			// Test IsPrePolicy
			gotPre, err := pph.IsPrePolicy()
			if err != nil {
				t.Errorf("IsPrePolicy() unexpected error: %v", err)
			}
			if gotPre != tt.expectPrePolicy {
				t.Errorf("IsPrePolicy() = %v, want %v", gotPre, tt.expectPrePolicy)
			}

			// Test IsPostPolicy
			gotPost, err := pph.IsPostPolicy()
			if err != nil {
				t.Errorf("IsPostPolicy() unexpected error: %v", err)
			}
			if gotPost != tt.expectPostPolicy {
				t.Errorf("IsPostPolicy() = %v, want %v", gotPost, tt.expectPostPolicy)
			}

			// Test IsAdjRIBInPre
			gotRIBInPre, err := pph.IsAdjRIBInPre()
			if err != nil {
				t.Errorf("IsAdjRIBInPre() unexpected error: %v", err)
			}
			if gotRIBInPre != tt.expectRIBInPre {
				t.Errorf("IsAdjRIBInPre() = %v, want %v", gotRIBInPre, tt.expectRIBInPre)
			}

			// Test IsAdjRIBInPost
			gotRIBInPost, err := pph.IsAdjRIBInPost()
			if err != nil {
				t.Errorf("IsAdjRIBInPost() unexpected error: %v", err)
			}
			if gotRIBInPost != tt.expectRIBInPost {
				t.Errorf("IsAdjRIBInPost() = %v, want %v", gotRIBInPost, tt.expectRIBInPost)
			}

			// Test IsAdjRIBOutPre
			gotRIBOutPre, err := pph.IsAdjRIBOutPre()
			if err != nil {
				t.Errorf("IsAdjRIBOutPre() unexpected error: %v", err)
			}
			if gotRIBOutPre != tt.expectRIBOutPre {
				t.Errorf("IsAdjRIBOutPre() = %v, want %v", gotRIBOutPre, tt.expectRIBOutPre)
			}

			// Test IsAdjRIBOutPost
			gotRIBOutPost, err := pph.IsAdjRIBOutPost()
			if err != nil {
				t.Errorf("IsAdjRIBOutPost() unexpected error: %v", err)
			}
			if gotRIBOutPost != tt.expectRIBOutPost {
				t.Errorf("IsAdjRIBOutPost() = %v, want %v", gotRIBOutPost, tt.expectRIBOutPost)
			}
		})
	}
}

// TestPerPeerHeaderFlagsMutualExclusivity ensures the 4 RIB types are mutually exclusive
// Per RFC 7854/8671: Only ONE of the 4 states should be true at any time
func TestPerPeerHeaderFlagsMutualExclusivity(t *testing.T) {
	tests := []struct {
		name      string
		flagsByte byte
	}{
		{name: "Adj-RIB-In Pre-Policy (O=0, L=0)", flagsByte: 0x00},
		{name: "Adj-RIB-Out Pre-Policy (O=1, L=0)", flagsByte: 0x10},
		{name: "Adj-RIB-In Post-Policy (O=0, L=1)", flagsByte: 0x40},
		{name: "Adj-RIB-Out Post-Policy (O=1, L=1)", flagsByte: 0x50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pph := &PerPeerHeader{
				PeerType:          PeerType0,
				flagV:             tt.flagsByte&0x80 == 0x80,
				flagL:             tt.flagsByte&0x40 == 0x40,
				flagA:             tt.flagsByte&0x20 == 0x20,
				flagO:             tt.flagsByte&0x10 == 0x10,
				PeerDistinguisher: make([]byte, 8),
				PeerAddress:       make([]byte, 16),
				PeerBGPID:         make([]byte, 4),
				PeerTimestamp:     make([]byte, 8),
			}

			// Count how many RIB states return true
			trueCount := 0
			states := make(map[string]bool)

			if ribInPre, _ := pph.IsAdjRIBInPre(); ribInPre {
				trueCount++
				states["IsAdjRIBInPre"] = true
			}
			if ribInPost, _ := pph.IsAdjRIBInPost(); ribInPost {
				trueCount++
				states["IsAdjRIBInPost"] = true
			}
			if ribOutPre, _ := pph.IsAdjRIBOutPre(); ribOutPre {
				trueCount++
				states["IsAdjRIBOutPre"] = true
			}
			if ribOutPost, _ := pph.IsAdjRIBOutPost(); ribOutPost {
				trueCount++
				states["IsAdjRIBOutPost"] = true
			}

			if trueCount != 1 {
				t.Errorf("Expected exactly 1 RIB state to be true, got %d: %v", trueCount, states)
			}
		})
	}
}

// TestLocRIBFiltered tests Loc-RIB (PeerType3) handling per RFC 9069
func TestLocRIBFiltered(t *testing.T) {
	tests := []struct {
		name           string
		flagsByte      byte
		expectFiltered bool
	}{
		{
			name:           "RFC 9069: Loc-RIB Non-Filtered (F=0)",
			flagsByte:      0x00,
			expectFiltered: false,
		},
		{
			name:           "RFC 9069: Loc-RIB Filtered (F=1)",
			flagsByte:      0x80,
			expectFiltered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pph := &PerPeerHeader{
				PeerType:          PeerType3,
				flagF:             tt.flagsByte&0x80 == 0x80,
				PeerDistinguisher: make([]byte, 8),
				PeerAddress:       make([]byte, 16),
				PeerBGPID:         make([]byte, 4),
				PeerTimestamp:     make([]byte, 8),
			}

			// Test IsLocRIBFiltered
			gotFiltered, err := pph.IsLocRIBFiltered()
			if err != nil {
				t.Errorf("IsLocRIBFiltered() unexpected error: %v", err)
			}
			if gotFiltered != tt.expectFiltered {
				t.Errorf("IsLocRIBFiltered() = %v, want %v", gotFiltered, tt.expectFiltered)
			}

			// Ensure Adj-RIB functions return error for PeerType3
			if _, err := pph.IsAdjRIBIn(); err != ErrInvFlagRequestForPeerType {
				t.Errorf("IsAdjRIBIn() should return ErrInvFlagRequestForPeerType for PeerType3, got: %v", err)
			}
			if _, err := pph.IsAdjRIBOut(); err != ErrInvFlagRequestForPeerType {
				t.Errorf("IsAdjRIBOut() should return ErrInvFlagRequestForPeerType for PeerType3, got: %v", err)
			}
			if _, err := pph.IsAdjRIBInPre(); err != ErrInvFlagRequestForPeerType {
				t.Errorf("IsAdjRIBInPre() should return ErrInvFlagRequestForPeerType for PeerType3, got: %v", err)
			}
			if _, err := pph.IsAdjRIBInPost(); err != ErrInvFlagRequestForPeerType {
				t.Errorf("IsAdjRIBInPost() should return ErrInvFlagRequestForPeerType for PeerType3, got: %v", err)
			}
			if _, err := pph.IsAdjRIBOutPre(); err != ErrInvFlagRequestForPeerType {
				t.Errorf("IsAdjRIBOutPre() should return ErrInvFlagRequestForPeerType for PeerType3, got: %v", err)
			}
			if _, err := pph.IsAdjRIBOutPost(); err != ErrInvFlagRequestForPeerType {
				t.Errorf("IsAdjRIBOutPost() should return ErrInvFlagRequestForPeerType for PeerType3, got: %v", err)
			}
		})
	}
}

// TestUnmarshalPerPeerHeader tests full parsing of Per-Peer Header
func TestUnmarshalPerPeerHeader(t *testing.T) {
	// Real BMP Per-Peer Header from PCAP (42 bytes)
	// PeerType=0, Flags=0x50 (O=1, L=1 = Adj-RIB-Out Post-Policy)
	data := []byte{
		0x00,                                           // Peer Type = 0 (Global Instance)
		0x50,                                           // Flags: 0101 0000 (V=0, L=1, A=0, O=1)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Peer Distinguisher (8 bytes, all zeros)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Peer Address (16 bytes, IPv4-mapped)
		0x00, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01, // ...continued (192.168.1.1)
		0x00, 0x00, 0xFD, 0xE8, // Peer AS = 65000
		0xC0, 0xA8, 0x01, 0x01, // Peer BGP ID (192.168.1.1)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp (8 bytes, epoch)
	}

	pph, err := UnmarshalPerPeerHeader(data)
	if err != nil {
		t.Fatalf("UnmarshalPerPeerHeader() error: %v", err)
	}

	// Verify PeerType
	if pph.PeerType != PeerType0 {
		t.Errorf("PeerType = %v, want %v", pph.PeerType, PeerType0)
	}

	// Verify Peer AS
	if pph.PeerAS != 65000 {
		t.Errorf("PeerAS = %d, want 65000", pph.PeerAS)
	}

	// Verify flags interpretation (flags=0x50 = O=1, L=1)
	// Per RFC 8671: This is Adj-RIB-Out Post-Policy
	if gotIPv6 := pph.IsRemotePeerIPv6(); gotIPv6 != false {
		t.Errorf("IsRemotePeerIPv6() = %v, want false (V=0)", gotIPv6)
	}

	if got4Byte, _ := pph.Is4ByteASN(); got4Byte != false {
		t.Errorf("Is4ByteASN() = %v, want false (A=0)", got4Byte)
	}

	if gotRIBIn, _ := pph.IsAdjRIBIn(); gotRIBIn != false {
		t.Errorf("IsAdjRIBIn() = %v, want false (O=1)", gotRIBIn)
	}

	if gotRIBOut, _ := pph.IsAdjRIBOut(); gotRIBOut != true {
		t.Errorf("IsAdjRIBOut() = %v, want true (O=1)", gotRIBOut)
	}

	if gotPre, _ := pph.IsPrePolicy(); gotPre != false {
		t.Errorf("IsPrePolicy() = %v, want false (L=1)", gotPre)
	}

	if gotPost, _ := pph.IsPostPolicy(); gotPost != true {
		t.Errorf("IsPostPolicy() = %v, want true (L=1)", gotPost)
	}

	// Critical test: Verify the original bug is fixed
	// flags=0x50 should ONLY have IsAdjRIBOutPost=true, not IsAdjRIBInPost
	if gotRIBInPost, _ := pph.IsAdjRIBInPost(); gotRIBInPost != false {
		t.Errorf("BUG NOT FIXED: IsAdjRIBInPost() = %v, want false (O=1, L=1 is RIB-Out, not RIB-In)", gotRIBInPost)
	}

	if gotRIBOutPost, _ := pph.IsAdjRIBOutPost(); gotRIBOutPost != true {
		t.Errorf("IsAdjRIBOutPost() = %v, want true (O=1, L=1)", gotRIBOutPost)
	}

	// Verify mutual exclusivity
	trueCount := 0
	if ribInPre, _ := pph.IsAdjRIBInPre(); ribInPre {
		trueCount++
	}
	if ribInPost, _ := pph.IsAdjRIBInPost(); ribInPost {
		trueCount++
	}
	if ribOutPre, _ := pph.IsAdjRIBOutPre(); ribOutPre {
		trueCount++
	}
	if ribOutPost, _ := pph.IsAdjRIBOutPost(); ribOutPost {
		trueCount++
	}

	if trueCount != 1 {
		t.Errorf("Expected exactly 1 RIB state to be true, got %d", trueCount)
	}
}
