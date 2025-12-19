package bgp

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestType5_RouteTarget(t *testing.T) {
	// Test Route Target (subtype 0x02) with IPv6 address 2001:db8::1 and local admin 100
	value := make([]byte, 18)
	ipv6 := net.ParseIP("2001:db8::1")
	copy(value[0:16], ipv6)
	binary.BigEndian.PutUint16(value[16:18], 100)

	result := type5(0x02, value)
	expected := "rt=2001:db8::1:100"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestType5_RouteOrigin(t *testing.T) {
	// Test Route Origin (subtype 0x03) with IPv6 address 2001:db8::2 and local admin 200
	value := make([]byte, 18)
	ipv6 := net.ParseIP("2001:db8::2")
	copy(value[0:16], ipv6)
	binary.BigEndian.PutUint16(value[16:18], 200)

	result := type5(0x03, value)
	expected := "ro=2001:db8::2:200"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestType5_UnknownSubtype(t *testing.T) {
	// Test unknown subtype (0x99) with IPv6 address fe80::1 and local admin 300
	value := make([]byte, 18)
	ipv6 := net.ParseIP("fe80::1")
	copy(value[0:16], ipv6)
	binary.BigEndian.PutUint16(value[16:18], 300)

	result := type5(0x99, value)
	expected := "subtype-153=fe80::1:300"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestType5_InvalidLength(t *testing.T) {
	// Test with insufficient data (less than 18 bytes)
	value := make([]byte, 10)

	result := type5(0x02, value)
	expected := "invalid-ipv6-ec-length"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestType5_FullIPv6Address(t *testing.T) {
	// Test with full IPv6 address 2001:0db8:85a3:0000:0000:8a2e:0370:7334
	value := make([]byte, 18)
	ipv6 := net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	copy(value[0:16], ipv6)
	binary.BigEndian.PutUint16(value[16:18], 65535)

	result := type5(0x02, value)
	expected := "rt=2001:db8:85a3::8a2e:370:7334:65535"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestType5_LocalhostIPv6(t *testing.T) {
	// Test with ::1 (localhost)
	value := make([]byte, 18)
	ipv6 := net.ParseIP("::1")
	copy(value[0:16], ipv6)
	binary.BigEndian.PutUint16(value[16:18], 1)

	result := type5(0x02, value)
	expected := "rt=::1:1"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestType5_ZeroLocalAdmin(t *testing.T) {
	// Test with local administrator = 0
	value := make([]byte, 18)
	ipv6 := net.ParseIP("2001:db8::1")
	copy(value[0:16], ipv6)
	binary.BigEndian.PutUint16(value[16:18], 0)

	result := type5(0x02, value)
	expected := "rt=2001:db8::1:0"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestType5_MaxLocalAdmin(t *testing.T) {
	// Test with maximum local administrator value (65535)
	value := make([]byte, 18)
	ipv6 := net.ParseIP("ff02::1")
	copy(value[0:16], ipv6)
	binary.BigEndian.PutUint16(value[16:18], 65535)

	result := type5(0x03, value)
	expected := "ro=ff02::1:65535"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestExtCommunity_Type5Integration(t *testing.T) {
	// Test integration with ExtCommunity.String()
	// Create Extended Community with Type 0x05, Subtype 0x02
	subtype := uint8(0x02)
	ec := ExtCommunity{
		Type:    0x05,
		SubType: &subtype,
	}
	ec.Value = make([]byte, 18)
	ipv6 := net.ParseIP("2001:db8::1")
	copy(ec.Value[0:16], ipv6)
	binary.BigEndian.PutUint16(ec.Value[16:18], 100)

	result := ec.String()
	expected := "rt=2001:db8::1:100"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestType5_CompressedIPv6(t *testing.T) {
	// Test with compressed IPv6 notation (::ffff:192.0.2.1 - IPv4-mapped IPv6)
	// Note: Go's net.IP.String() automatically converts IPv4-mapped IPv6 to IPv4 format
	value := make([]byte, 18)
	ipv6 := net.ParseIP("::ffff:192.0.2.1")
	copy(value[0:16], ipv6)
	binary.BigEndian.PutUint16(value[16:18], 500)

	result := type5(0x02, value)
	expected := "rt=192.0.2.1:500"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}
