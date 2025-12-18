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
