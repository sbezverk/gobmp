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
	// IPv4 prefix data (31 bytes) — passes min check (23) but fails case 34 guard
	b := make([]byte, 31)
	b[0] = 0x00
	b[1] = 0x00
	b[22] = 24
	_, err := UnmarshalEVPNIPPrefix(b, 34)
	if err == nil {
		t.Fatal("expected error for short Type 5 IPv4")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUnmarshalEVPNIPPrefix_IPv6TooShort(t *testing.T) {
	// 30 bytes — passes min check (23) but fails case 58 guard
	b := make([]byte, 30)
	b[0] = 0x00
	b[1] = 0x00
	_, err := UnmarshalEVPNIPPrefix(b, 58)
	if err == nil {
		t.Fatal("expected error for short Type 5 IPv6")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error: %v", err)
	}
}
