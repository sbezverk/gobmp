package evpn

import (
	"strings"
	"testing"
)

func TestUnmarshalEVPNNLRI_TruncatedHeader(t *testing.T) {
	_, err := UnmarshalEVPNNLRI([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for truncated NLRI header")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEVPNTypeBoundsChecks(t *testing.T) {
	tests := []struct {
		name    string
		fn      func() error
		wantSub string
	}{
		// Minimum header too short
		{"Type 1 header too short", func() error { _, e := UnmarshalEVPNEthAutoDiscovery(make([]byte, 10)); return e }, "need at least 22"},
		{"Type 2 header too short", func() error { _, e := UnmarshalEVPNMACIPAdvertisement(make([]byte, 20)); return e }, "need at least 24"},
		{"Type 3 header too short", func() error { _, e := UnmarshalEVPNInclusiveMulticastEthTag(make([]byte, 10)); return e }, "need at least 13"},
		{"Type 4 header too short", func() error { _, e := UnmarshalEVPNEthernetSegment(make([]byte, 15)); return e }, "need at least 19"},
		{"Type 5 header too short", func() error { _, e := UnmarshalEVPNIPPrefix(make([]byte, 20), 34); return e }, "need at least 23"},
		// Type 5 per-branch checks
		{"Type 5 IPv4 branch too short", func() error {
			b := make([]byte, 31)
			_, e := UnmarshalEVPNIPPrefix(b, 34)
			return e
		}, "need 34 bytes"},
		{"Type 5 IPv6 branch too short", func() error {
			b := make([]byte, 30)
			_, e := UnmarshalEVPNIPPrefix(b, 58)
			return e
		}, "need 58 bytes"},
		// Variable-length field truncation (header present, body truncated)
		{"Type 3 IP address truncated", func() error {
			// 13 bytes min header, IPAddrLength=32 (4 bytes), but no IP bytes
			b := make([]byte, 13)
			b[12] = 32 // IPAddrLength at offset 12 (RD=8 + EthTag=4)
			_, e := UnmarshalEVPNInclusiveMulticastEthTag(b)
			return e
		}, "truncated"},
		{"Type 4 IP address truncated", func() error {
			// 19 bytes min header, IPAddrLength=128 (16 bytes), but no IP bytes
			b := make([]byte, 19)
			b[18] = 128 // IPAddrLength at offset 18 (RD=8 + ESI=10)
			_, e := UnmarshalEVPNEthernetSegment(b)
			return e
		}, "truncated"},
		{"Type 2 MAC truncated", func() error {
			// 24 bytes min header, MACAddrLength=48 (6 bytes) at offset 22
			b := make([]byte, 24)
			b[22] = 48 // MACAddrLength at offset 22 (RD=8 + ESI=10 + EthTag=4)
			_, e := UnmarshalEVPNMACIPAdvertisement(b)
			return e
		}, "truncated"},
		{"Type 2 IP truncated", func() error {
			// Header + MAC(0) + IPAddrLength=128 but no IP bytes
			b := make([]byte, 24)
			b[22] = 0  // MACAddrLength=0
			b[23] = 128 // IPAddrLength=128 (16 bytes needed)
			_, e := UnmarshalEVPNMACIPAdvertisement(b)
			return e
		}, "truncated"},
		{"Type 1 trailing bytes", func() error {
			// Valid Type 1 with label + 1 extra byte
			b := make([]byte, 26)
			b[24] = 0x00 // label byte 1
			b[25] = 0x01 // label BoS=1 (bottom of stack) - wait, need 3 bytes for label
			// Actually need: 22 header + 3 label + 1 trailing = 26
			b2 := make([]byte, 26)
			b2[24] = 0x01 // label BoS bit set in last nibble
			_, e := UnmarshalEVPNEthAutoDiscovery(b2)
			return e
		}, "trailing"},
		{"Type 2 trailing bytes", func() error {
			// Header(24) + MAC(0) + IPLen(0) + label(3) + 1 trailing
			b := make([]byte, 28)
			b[22] = 0  // MACAddrLength=0
			b[23] = 0  // IPAddrLength=0
			b[24] = 0  // label byte 1
			b[25] = 0  // label byte 2
			b[26] = 1  // label byte 3 with BoS
			_, e := UnmarshalEVPNMACIPAdvertisement(b)
			return e
		}, "trailing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}
