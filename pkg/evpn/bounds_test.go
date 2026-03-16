package evpn

import (
	"strings"
	"testing"
)

func TestUnmarshalEVPNNLRI_TruncatedHeader(t *testing.T) {
	// Only 1 byte — not enough for type+length
	_, err := UnmarshalEVPNNLRI([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for truncated NLRI header")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmarshalEVPNEthAutoDiscovery_TooShort(t *testing.T) {
	// Type 1 needs at least 22 bytes
	_, err := UnmarshalEVPNEthAutoDiscovery(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short Type 1")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmarshalEVPNMACIPAdvertisement_TooShort(t *testing.T) {
	// Type 2 needs at least 24 bytes
	_, err := UnmarshalEVPNMACIPAdvertisement(make([]byte, 20))
	if err == nil {
		t.Fatal("expected error for short Type 2")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmarshalEVPNInclusiveMulticastEthTag_TooShort(t *testing.T) {
	// Type 3 needs at least 13 bytes
	_, err := UnmarshalEVPNInclusiveMulticastEthTag(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short Type 3")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmarshalEVPNEthernetSegment_TooShort(t *testing.T) {
	// Type 4 needs at least 19 bytes
	_, err := UnmarshalEVPNEthernetSegment(make([]byte, 15))
	if err == nil {
		t.Fatal("expected error for short Type 4")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmarshalEVPNIPPrefix_TooShort(t *testing.T) {
	// Type 5 needs at least 23 bytes
	_, err := UnmarshalEVPNIPPrefix(make([]byte, 20), 34)
	if err == nil {
		t.Fatal("expected error for short Type 5")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmarshalEVPNIPPrefix_MissingLabel(t *testing.T) {
	// Valid IPv4 prefix data (31 bytes) but no label bytes
	// RD(8) + ESI(10) + EthTag(4) + IPLen(1) + IP(4) + GW(4) = 31
	b := make([]byte, 31)
	// Set RD type to 0 (valid)
	b[0] = 0x00
	b[1] = 0x00
	// IPAddrLength at offset 22
	b[22] = 24
	_, err := UnmarshalEVPNIPPrefix(b, 34)
	if err == nil {
		t.Fatal("expected error for missing label bytes")
	}
	if !strings.Contains(err.Error(), "not enough bytes for label") {
		t.Errorf("unexpected error: %v", err)
	}
}
