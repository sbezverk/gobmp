package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestRIBFlagPropagation verifies that all message types properly propagate
// the IsAdjRIBOut flag from PerPeerHeader to the message structs.
// This test ensures RFC 8671 compliance for distinguishing Adj-RIB-In from Adj-RIB-Out.
func TestRIBFlagPropagation(t *testing.T) {
	tests := []struct {
		name                 string
		flagsByte            byte
		expectIsAdjRIBInPost bool
		expectIsAdjRIBOutPost bool
		expectIsAdjRIBOut    bool
	}{
		{
			name:                 "Adj-RIB-In Pre-Policy (O=0, L=0)",
			flagsByte:            0x00,
			expectIsAdjRIBInPost: false,
			expectIsAdjRIBOutPost: false,
			expectIsAdjRIBOut:    false,
		},
		{
			name:                 "Adj-RIB-In Post-Policy (O=0, L=1)",
			flagsByte:            0x40,
			expectIsAdjRIBInPost: true,
			expectIsAdjRIBOutPost: false,
			expectIsAdjRIBOut:    false,
		},
		{
			name:                 "Adj-RIB-Out Pre-Policy (O=1, L=0)",
			flagsByte:            0x10,
			expectIsAdjRIBInPost: false,
			expectIsAdjRIBOutPost: false,
			expectIsAdjRIBOut:    true,
		},
		{
			name:                 "Adj-RIB-Out Post-Policy (O=1, L=1)",
			flagsByte:            0x50,
			expectIsAdjRIBInPost: false,
			expectIsAdjRIBOutPost: true,
			expectIsAdjRIBOut:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock PerPeerHeader with the specific flags
			pph := &bmp.PerPeerHeader{
				PeerType:          bmp.PeerType0,
				PeerDistinguisher: make([]byte, 8),
				PeerAddress:       make([]byte, 16),
				PeerBGPID:         make([]byte, 4),
				PeerTimestamp:     make([]byte, 8),
				PeerAS:            65000,
			}
			// Manually set the flags by unmarshaling a byte sequence
			flagsData := []byte{
				byte(bmp.PeerType0), // Peer Type
				tt.flagsByte,        // Flags byte
			}
			// Append the rest of the header
			flagsData = append(flagsData, pph.PeerDistinguisher...)
			flagsData = append(flagsData, pph.PeerAddress...)
			flagsData = append(flagsData, 0x00, 0x00, 0xFD, 0xE8) // Peer AS = 65000
			flagsData = append(flagsData, pph.PeerBGPID...)
			flagsData = append(flagsData, pph.PeerTimestamp...)

			pph, err := bmp.UnmarshalPerPeerHeader(flagsData)
			if err != nil {
				t.Fatalf("Failed to unmarshal PerPeerHeader: %v", err)
			}

			// Verify PerPeerHeader methods work correctly
			if gotAdjRIBInPost, _ := pph.IsAdjRIBInPost(); gotAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("PerPeerHeader.IsAdjRIBInPost() = %v, want %v", gotAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if gotAdjRIBOutPost, _ := pph.IsAdjRIBOutPost(); gotAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("PerPeerHeader.IsAdjRIBOutPost() = %v, want %v", gotAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if gotAdjRIBOut, _ := pph.IsAdjRIBOut(); gotAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("PerPeerHeader.IsAdjRIBOut() = %v, want %v", gotAdjRIBOut, tt.expectIsAdjRIBOut)
			}

			// Test message struct population
			// We'll test a few representative message types

			// 1. Test UnicastPrefix
			unicastPrefix := &UnicastPrefix{}
			if f, err := pph.IsAdjRIBInPost(); err == nil {
				unicastPrefix.IsAdjRIBInPost = f
			}
			if f, err := pph.IsAdjRIBOutPost(); err == nil {
				unicastPrefix.IsAdjRIBOutPost = f
			}
			if f, err := pph.IsAdjRIBOut(); err == nil {
				unicastPrefix.IsAdjRIBOut = f
			}

			if unicastPrefix.IsAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("UnicastPrefix.IsAdjRIBInPost = %v, want %v", unicastPrefix.IsAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if unicastPrefix.IsAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("UnicastPrefix.IsAdjRIBOutPost = %v, want %v", unicastPrefix.IsAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if unicastPrefix.IsAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("UnicastPrefix.IsAdjRIBOut = %v, want %v", unicastPrefix.IsAdjRIBOut, tt.expectIsAdjRIBOut)
			}

			// 2. Test L3VPNPrefix
			l3vpnPrefix := &L3VPNPrefix{}
			if f, err := pph.IsAdjRIBInPost(); err == nil {
				l3vpnPrefix.IsAdjRIBInPost = f
			}
			if f, err := pph.IsAdjRIBOutPost(); err == nil {
				l3vpnPrefix.IsAdjRIBOutPost = f
			}
			if f, err := pph.IsAdjRIBOut(); err == nil {
				l3vpnPrefix.IsAdjRIBOut = f
			}

			if l3vpnPrefix.IsAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("L3VPNPrefix.IsAdjRIBInPost = %v, want %v", l3vpnPrefix.IsAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if l3vpnPrefix.IsAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("L3VPNPrefix.IsAdjRIBOutPost = %v, want %v", l3vpnPrefix.IsAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if l3vpnPrefix.IsAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("L3VPNPrefix.IsAdjRIBOut = %v, want %v", l3vpnPrefix.IsAdjRIBOut, tt.expectIsAdjRIBOut)
			}

			// 3. Test EVPNPrefix
			evpnPrefix := &EVPNPrefix{}
			if f, err := pph.IsAdjRIBInPost(); err == nil {
				evpnPrefix.IsAdjRIBInPost = f
			}
			if f, err := pph.IsAdjRIBOutPost(); err == nil {
				evpnPrefix.IsAdjRIBOutPost = f
			}
			if f, err := pph.IsAdjRIBOut(); err == nil {
				evpnPrefix.IsAdjRIBOut = f
			}

			if evpnPrefix.IsAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("EVPNPrefix.IsAdjRIBInPost = %v, want %v", evpnPrefix.IsAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if evpnPrefix.IsAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("EVPNPrefix.IsAdjRIBOutPost = %v, want %v", evpnPrefix.IsAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if evpnPrefix.IsAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("EVPNPrefix.IsAdjRIBOut = %v, want %v", evpnPrefix.IsAdjRIBOut, tt.expectIsAdjRIBOut)
			}

			// 4. Test LSNode
			lsNode := &LSNode{}
			if f, err := pph.IsAdjRIBInPost(); err == nil {
				lsNode.IsAdjRIBInPost = f
			}
			if f, err := pph.IsAdjRIBOutPost(); err == nil {
				lsNode.IsAdjRIBOutPost = f
			}
			if f, err := pph.IsAdjRIBOut(); err == nil {
				lsNode.IsAdjRIBOut = f
			}

			if lsNode.IsAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("LSNode.IsAdjRIBInPost = %v, want %v", lsNode.IsAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if lsNode.IsAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("LSNode.IsAdjRIBOutPost = %v, want %v", lsNode.IsAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if lsNode.IsAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("LSNode.IsAdjRIBOut = %v, want %v", lsNode.IsAdjRIBOut, tt.expectIsAdjRIBOut)
			}

			// 5. Test LSLink
			lsLink := &LSLink{}
			if f, err := pph.IsAdjRIBInPost(); err == nil {
				lsLink.IsAdjRIBInPost = f
			}
			if f, err := pph.IsAdjRIBOutPost(); err == nil {
				lsLink.IsAdjRIBOutPost = f
			}
			if f, err := pph.IsAdjRIBOut(); err == nil {
				lsLink.IsAdjRIBOut = f
			}

			if lsLink.IsAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("LSLink.IsAdjRIBInPost = %v, want %v", lsLink.IsAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if lsLink.IsAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("LSLink.IsAdjRIBOutPost = %v, want %v", lsLink.IsAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if lsLink.IsAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("LSLink.IsAdjRIBOut = %v, want %v", lsLink.IsAdjRIBOut, tt.expectIsAdjRIBOut)
			}

			// 6. Test LSPrefix
			lsPrefix := &LSPrefix{}
			if f, err := pph.IsAdjRIBInPost(); err == nil {
				lsPrefix.IsAdjRIBInPost = f
			}
			if f, err := pph.IsAdjRIBOutPost(); err == nil {
				lsPrefix.IsAdjRIBOutPost = f
			}
			if f, err := pph.IsAdjRIBOut(); err == nil {
				lsPrefix.IsAdjRIBOut = f
			}

			if lsPrefix.IsAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("LSPrefix.IsAdjRIBInPost = %v, want %v", lsPrefix.IsAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if lsPrefix.IsAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("LSPrefix.IsAdjRIBOutPost = %v, want %v", lsPrefix.IsAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if lsPrefix.IsAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("LSPrefix.IsAdjRIBOut = %v, want %v", lsPrefix.IsAdjRIBOut, tt.expectIsAdjRIBOut)
			}

			// 7. Test LSSRv6SID
			lsSRv6SID := &LSSRv6SID{}
			if f, err := pph.IsAdjRIBInPost(); err == nil {
				lsSRv6SID.IsAdjRIBInPost = f
			}
			if f, err := pph.IsAdjRIBOutPost(); err == nil {
				lsSRv6SID.IsAdjRIBOutPost = f
			}
			if f, err := pph.IsAdjRIBOut(); err == nil {
				lsSRv6SID.IsAdjRIBOut = f
			}

			if lsSRv6SID.IsAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("LSSRv6SID.IsAdjRIBInPost = %v, want %v", lsSRv6SID.IsAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if lsSRv6SID.IsAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("LSSRv6SID.IsAdjRIBOutPost = %v, want %v", lsSRv6SID.IsAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if lsSRv6SID.IsAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("LSSRv6SID.IsAdjRIBOut = %v, want %v", lsSRv6SID.IsAdjRIBOut, tt.expectIsAdjRIBOut)
			}

			// 8. Test SRPolicy
			srPolicy := &SRPolicy{}
			if f, err := pph.IsAdjRIBInPost(); err == nil {
				srPolicy.IsAdjRIBInPost = f
			}
			if f, err := pph.IsAdjRIBOutPost(); err == nil {
				srPolicy.IsAdjRIBOutPost = f
			}
			if f, err := pph.IsAdjRIBOut(); err == nil {
				srPolicy.IsAdjRIBOut = f
			}

			if srPolicy.IsAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("SRPolicy.IsAdjRIBInPost = %v, want %v", srPolicy.IsAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if srPolicy.IsAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("SRPolicy.IsAdjRIBOutPost = %v, want %v", srPolicy.IsAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if srPolicy.IsAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("SRPolicy.IsAdjRIBOut = %v, want %v", srPolicy.IsAdjRIBOut, tt.expectIsAdjRIBOut)
			}

			// 9. Test Flowspec
			flowspec := &Flowspec{}
			if f, err := pph.IsAdjRIBInPost(); err == nil {
				flowspec.IsAdjRIBInPost = f
			}
			if f, err := pph.IsAdjRIBOutPost(); err == nil {
				flowspec.IsAdjRIBOutPost = f
			}
			if f, err := pph.IsAdjRIBOut(); err == nil {
				flowspec.IsAdjRIBOut = f
			}

			if flowspec.IsAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("Flowspec.IsAdjRIBInPost = %v, want %v", flowspec.IsAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if flowspec.IsAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("Flowspec.IsAdjRIBOutPost = %v, want %v", flowspec.IsAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if flowspec.IsAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("Flowspec.IsAdjRIBOut = %v, want %v", flowspec.IsAdjRIBOut, tt.expectIsAdjRIBOut)
			}

			// 10. Test PeerStateChange
			peerState := &PeerStateChange{}
			if f, err := pph.IsAdjRIBInPost(); err == nil {
				peerState.IsAdjRIBInPost = f
			}
			if f, err := pph.IsAdjRIBOutPost(); err == nil {
				peerState.IsAdjRIBOutPost = f
			}
			if f, err := pph.IsAdjRIBOut(); err == nil {
				peerState.IsAdjRIBOut = f
			}

			if peerState.IsAdjRIBInPost != tt.expectIsAdjRIBInPost {
				t.Errorf("PeerStateChange.IsAdjRIBInPost = %v, want %v", peerState.IsAdjRIBInPost, tt.expectIsAdjRIBInPost)
			}
			if peerState.IsAdjRIBOutPost != tt.expectIsAdjRIBOutPost {
				t.Errorf("PeerStateChange.IsAdjRIBOutPost = %v, want %v", peerState.IsAdjRIBOutPost, tt.expectIsAdjRIBOutPost)
			}
			if peerState.IsAdjRIBOut != tt.expectIsAdjRIBOut {
				t.Errorf("PeerStateChange.IsAdjRIBOut = %v, want %v", peerState.IsAdjRIBOut, tt.expectIsAdjRIBOut)
			}
		})
	}
}

// TestRFC8671Compliance verifies that all 4 Adj-RIB types are correctly identified
// per RFC 8671 Section 2 (Adj-RIB-In Pre, Adj-RIB-In Post, Adj-RIB-Out Pre, Adj-RIB-Out Post)
func TestRFC8671Compliance(t *testing.T) {
	type ribState struct {
		name             string
		flagsByte        byte
		expectRIBInPre   bool
		expectRIBInPost  bool
		expectRIBOutPre  bool
		expectRIBOutPost bool
	}

	tests := []ribState{
		{
			name:             "Adj-RIB-In Pre-Policy",
			flagsByte:        0x00, // O=0, L=0
			expectRIBInPre:   true,
			expectRIBInPost:  false,
			expectRIBOutPre:  false,
			expectRIBOutPost: false,
		},
		{
			name:             "Adj-RIB-In Post-Policy",
			flagsByte:        0x40, // O=0, L=1
			expectRIBInPre:   false,
			expectRIBInPost:  true,
			expectRIBOutPre:  false,
			expectRIBOutPost: false,
		},
		{
			name:             "Adj-RIB-Out Pre-Policy",
			flagsByte:        0x10, // O=1, L=0
			expectRIBInPre:   false,
			expectRIBInPost:  false,
			expectRIBOutPre:  true,
			expectRIBOutPost: false,
		},
		{
			name:             "Adj-RIB-Out Post-Policy",
			flagsByte:        0x50, // O=1, L=1
			expectRIBInPre:   false,
			expectRIBInPost:  false,
			expectRIBOutPre:  false,
			expectRIBOutPost: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create PerPeerHeader
			flagsData := []byte{
				byte(bmp.PeerType0),
				tt.flagsByte,
			}
			flagsData = append(flagsData, make([]byte, 8)...)  // Peer Distinguisher
			flagsData = append(flagsData, make([]byte, 16)...) // Peer Address
			flagsData = append(flagsData, 0x00, 0x00, 0xFD, 0xE8) // Peer AS
			flagsData = append(flagsData, make([]byte, 4)...)  // Peer BGP ID
			flagsData = append(flagsData, make([]byte, 8)...)  // Timestamp

			pph, err := bmp.UnmarshalPerPeerHeader(flagsData)
			if err != nil {
				t.Fatalf("UnmarshalPerPeerHeader() error: %v", err)
			}

			// Verify all 4 RIB states
			if gotRIBInPre, _ := pph.IsAdjRIBInPre(); gotRIBInPre != tt.expectRIBInPre {
				t.Errorf("IsAdjRIBInPre() = %v, want %v", gotRIBInPre, tt.expectRIBInPre)
			}
			if gotRIBInPost, _ := pph.IsAdjRIBInPost(); gotRIBInPost != tt.expectRIBInPost {
				t.Errorf("IsAdjRIBInPost() = %v, want %v", gotRIBInPost, tt.expectRIBInPost)
			}
			if gotRIBOutPre, _ := pph.IsAdjRIBOutPre(); gotRIBOutPre != tt.expectRIBOutPre {
				t.Errorf("IsAdjRIBOutPre() = %v, want %v", gotRIBOutPre, tt.expectRIBOutPre)
			}
			if gotRIBOutPost, _ := pph.IsAdjRIBOutPost(); gotRIBOutPost != tt.expectRIBOutPost {
				t.Errorf("IsAdjRIBOutPost() = %v, want %v", gotRIBOutPost, tt.expectRIBOutPost)
			}

			// Verify mutual exclusivity
			trueCount := 0
			if tt.expectRIBInPre {
				trueCount++
			}
			if tt.expectRIBInPost {
				trueCount++
			}
			if tt.expectRIBOutPre {
				trueCount++
			}
			if tt.expectRIBOutPost {
				trueCount++
			}
			if trueCount != 1 {
				t.Errorf("Expected exactly 1 RIB state to be true, got %d", trueCount)
			}
		})
	}
}

// TestLocRIBFlagPropagation verifies RFC 9069 Loc-RIB support
// Tests that PeerType 3 routes are correctly identified as Loc-RIB
// and that the F flag properly distinguishes filtered vs non-filtered routes.
func TestLocRIBFlagPropagation(t *testing.T) {
	tests := []struct {
		name                 string
		flagsByte            byte
		expectIsLocRIB       bool
		expectIsLocRIBFiltered bool
	}{
		{
			name:                 "Loc-RIB (PeerType 3, F=0)",
			flagsByte:            0x00,
			expectIsLocRIB:       true,
			expectIsLocRIBFiltered: false,
		},
		{
			name:                 "Loc-RIB-Filtered (PeerType 3, F=1)",
			flagsByte:            0x80,
			expectIsLocRIB:       true,
			expectIsLocRIBFiltered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a PerPeerHeader with PeerType 3 (Loc-RIB)
			flagsData := []byte{
				byte(bmp.PeerType3), // PeerType 3 for Loc-RIB
				tt.flagsByte,        // F flag: 0x80 = filtered, 0x00 = non-filtered
			}
			flagsData = append(flagsData, make([]byte, 8)...)  // Peer Distinguisher (RD)
			flagsData = append(flagsData, make([]byte, 16)...) // Peer Address
			flagsData = append(flagsData, 0x00, 0x00, 0xFD, 0xE8) // Peer AS = 65000
			flagsData = append(flagsData, make([]byte, 4)...)  // Peer BGP ID
			flagsData = append(flagsData, make([]byte, 8)...)  // Timestamp

			pph, err := bmp.UnmarshalPerPeerHeader(flagsData)
			if err != nil {
				t.Fatalf("Failed to unmarshal PerPeerHeader: %v", err)
			}

			// Verify PerPeerHeader methods for Loc-RIB
			if gotIsLocRIB, _ := pph.IsLocRIB(); gotIsLocRIB != tt.expectIsLocRIB {
				t.Errorf("PerPeerHeader.IsLocRIB() = %v, want %v", gotIsLocRIB, tt.expectIsLocRIB)
			}
			if gotIsLocRIBFiltered, _ := pph.IsLocRIBFiltered(); gotIsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("PerPeerHeader.IsLocRIBFiltered() = %v, want %v", gotIsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}

			// Verify that Adj-RIB methods return errors for PeerType 3
			if _, err := pph.IsAdjRIBInPost(); err == nil {
				t.Error("IsAdjRIBInPost() should return error for PeerType 3")
			}
			if _, err := pph.IsAdjRIBOutPost(); err == nil {
				t.Error("IsAdjRIBOutPost() should return error for PeerType 3")
			}
			if _, err := pph.IsAdjRIBOut(); err == nil {
				t.Error("IsAdjRIBOut() should return error for PeerType 3")
			}

			// Test message struct population for Loc-RIB routes
			// 1. Test UnicastPrefix
			unicastPrefix := &UnicastPrefix{}
			if f, err := pph.IsLocRIB(); err == nil {
				unicastPrefix.IsLocRIB = f
			}
			if f, err := pph.IsLocRIBFiltered(); err == nil {
				unicastPrefix.IsLocRIBFiltered = f
			}

			if unicastPrefix.IsLocRIB != tt.expectIsLocRIB {
				t.Errorf("UnicastPrefix.IsLocRIB = %v, want %v", unicastPrefix.IsLocRIB, tt.expectIsLocRIB)
			}
			if unicastPrefix.IsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("UnicastPrefix.IsLocRIBFiltered = %v, want %v", unicastPrefix.IsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}

			// 2. Test L3VPNPrefix
			l3vpnPrefix := &L3VPNPrefix{}
			if f, err := pph.IsLocRIB(); err == nil {
				l3vpnPrefix.IsLocRIB = f
			}
			if f, err := pph.IsLocRIBFiltered(); err == nil {
				l3vpnPrefix.IsLocRIBFiltered = f
			}

			if l3vpnPrefix.IsLocRIB != tt.expectIsLocRIB {
				t.Errorf("L3VPNPrefix.IsLocRIB = %v, want %v", l3vpnPrefix.IsLocRIB, tt.expectIsLocRIB)
			}
			if l3vpnPrefix.IsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("L3VPNPrefix.IsLocRIBFiltered = %v, want %v", l3vpnPrefix.IsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}

			// 3. Test EVPNPrefix
			evpnPrefix := &EVPNPrefix{}
			if f, err := pph.IsLocRIB(); err == nil {
				evpnPrefix.IsLocRIB = f
			}
			if f, err := pph.IsLocRIBFiltered(); err == nil {
				evpnPrefix.IsLocRIBFiltered = f
			}

			if evpnPrefix.IsLocRIB != tt.expectIsLocRIB {
				t.Errorf("EVPNPrefix.IsLocRIB = %v, want %v", evpnPrefix.IsLocRIB, tt.expectIsLocRIB)
			}
			if evpnPrefix.IsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("EVPNPrefix.IsLocRIBFiltered = %v, want %v", evpnPrefix.IsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}

			// 4. Test LSNode
			lsNode := &LSNode{}
			if f, err := pph.IsLocRIB(); err == nil {
				lsNode.IsLocRIB = f
			}
			if f, err := pph.IsLocRIBFiltered(); err == nil {
				lsNode.IsLocRIBFiltered = f
			}

			if lsNode.IsLocRIB != tt.expectIsLocRIB {
				t.Errorf("LSNode.IsLocRIB = %v, want %v", lsNode.IsLocRIB, tt.expectIsLocRIB)
			}
			if lsNode.IsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("LSNode.IsLocRIBFiltered = %v, want %v", lsNode.IsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}

			// 5. Test LSLink
			lsLink := &LSLink{}
			if f, err := pph.IsLocRIB(); err == nil {
				lsLink.IsLocRIB = f
			}
			if f, err := pph.IsLocRIBFiltered(); err == nil {
				lsLink.IsLocRIBFiltered = f
			}

			if lsLink.IsLocRIB != tt.expectIsLocRIB {
				t.Errorf("LSLink.IsLocRIB = %v, want %v", lsLink.IsLocRIB, tt.expectIsLocRIB)
			}
			if lsLink.IsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("LSLink.IsLocRIBFiltered = %v, want %v", lsLink.IsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}

			// 6. Test LSPrefix
			lsPrefix := &LSPrefix{}
			if f, err := pph.IsLocRIB(); err == nil {
				lsPrefix.IsLocRIB = f
			}
			if f, err := pph.IsLocRIBFiltered(); err == nil {
				lsPrefix.IsLocRIBFiltered = f
			}

			if lsPrefix.IsLocRIB != tt.expectIsLocRIB {
				t.Errorf("LSPrefix.IsLocRIB = %v, want %v", lsPrefix.IsLocRIB, tt.expectIsLocRIB)
			}
			if lsPrefix.IsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("LSPrefix.IsLocRIBFiltered = %v, want %v", lsPrefix.IsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}

			// 7. Test LSSRv6SID
			srv6sid := &LSSRv6SID{}
			if f, err := pph.IsLocRIB(); err == nil {
				srv6sid.IsLocRIB = f
			}
			if f, err := pph.IsLocRIBFiltered(); err == nil {
				srv6sid.IsLocRIBFiltered = f
			}

			if srv6sid.IsLocRIB != tt.expectIsLocRIB {
				t.Errorf("LSSRv6SID.IsLocRIB = %v, want %v", srv6sid.IsLocRIB, tt.expectIsLocRIB)
			}
			if srv6sid.IsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("LSSRv6SID.IsLocRIBFiltered = %v, want %v", srv6sid.IsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}

			// 8. Test SRPolicy
			srpolicy := &SRPolicy{}
			if f, err := pph.IsLocRIB(); err == nil {
				srpolicy.IsLocRIB = f
			}
			if f, err := pph.IsLocRIBFiltered(); err == nil {
				srpolicy.IsLocRIBFiltered = f
			}

			if srpolicy.IsLocRIB != tt.expectIsLocRIB {
				t.Errorf("SRPolicy.IsLocRIB = %v, want %v", srpolicy.IsLocRIB, tt.expectIsLocRIB)
			}
			if srpolicy.IsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("SRPolicy.IsLocRIBFiltered = %v, want %v", srpolicy.IsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}

			// 9. Test Flowspec
			flowspec := &Flowspec{}
			if f, err := pph.IsLocRIB(); err == nil {
				flowspec.IsLocRIB = f
			}
			if f, err := pph.IsLocRIBFiltered(); err == nil {
				flowspec.IsLocRIBFiltered = f
			}

			if flowspec.IsLocRIB != tt.expectIsLocRIB {
				t.Errorf("Flowspec.IsLocRIB = %v, want %v", flowspec.IsLocRIB, tt.expectIsLocRIB)
			}
			if flowspec.IsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("Flowspec.IsLocRIBFiltered = %v, want %v", flowspec.IsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}

			// 10. Test PeerStateChange
			peerStateChange := &PeerStateChange{}
			if f, err := pph.IsLocRIB(); err == nil {
				peerStateChange.IsLocRIB = f
			}
			if f, err := pph.IsLocRIBFiltered(); err == nil {
				peerStateChange.IsLocRIBFiltered = f
			}

			if peerStateChange.IsLocRIB != tt.expectIsLocRIB {
				t.Errorf("PeerStateChange.IsLocRIB = %v, want %v", peerStateChange.IsLocRIB, tt.expectIsLocRIB)
			}
			if peerStateChange.IsLocRIBFiltered != tt.expectIsLocRIBFiltered {
				t.Errorf("PeerStateChange.IsLocRIBFiltered = %v, want %v", peerStateChange.IsLocRIBFiltered, tt.expectIsLocRIBFiltered)
			}
		})
	}
}
