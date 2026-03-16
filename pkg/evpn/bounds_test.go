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
