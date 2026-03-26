package flowspec

import (
	"encoding/json"
	"strings"
	"testing"
)

// RFC 8955 Section 6 — VPN FlowSpec (SAFI=134)
// Wire format: Length(1-2) + RD(8) + FlowSpec specs

// TestVPNFlowspecNLRI_IPv4_RDType0 validates VPN FlowSpec with RD Type 0 (2-byte ASN : 4-byte value).
func TestVPNFlowspecNLRI_IPv4_RDType0(t *testing.T) {
	// Length=13: RD(8) + Type1 dest prefix 10.0.1.0/24 (5 bytes)
	input := []byte{
		0x0d, // Length: 13
		// RD Type 0: ASN 100, value 200
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
		// Type 1: Destination Prefix 10.0.1.0/24
		0x01, 0x18, 0x0a, 0x00, 0x01,
	}
	nlri, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.RD != "100:200" {
		t.Errorf("RD = %q, want %q", nlri.RD, "100:200")
	}
	if len(nlri.Spec) != 1 {
		t.Fatalf("got %d specs, want 1", len(nlri.Spec))
	}
	if nlri.SpecHash == "" {
		t.Error("SpecHash should not be empty")
	}
	ps, ok := nlri.Spec[0].(*PrefixSpec)
	if !ok {
		t.Fatalf("spec[0] is %T, want *PrefixSpec", nlri.Spec[0])
	}
	if ps.SpecType != 1 || ps.PrefixLength != 24 {
		t.Errorf("spec type=%d prefixLen=%d, want type=1 prefixLen=24", ps.SpecType, ps.PrefixLength)
	}
}

// TestVPNFlowspecNLRI_IPv4_RDType1 validates VPN FlowSpec with RD Type 1 (IPv4 : 2-byte value).
func TestVPNFlowspecNLRI_IPv4_RDType1(t *testing.T) {
	// RD(8) + Type1 dest prefix 172.16.0.0/16 (4 bytes) = 12 total
	input := []byte{
		0x0c, // Length: 12
		// RD Type 1: IP 10.0.0.1, value 100
		0x00, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x64,
		// Type 1: Destination Prefix 172.16.0.0/16
		0x01, 0x10, 0xac, 0x10,
	}
	nlri, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.RD != "10.0.0.1:100" {
		t.Errorf("RD = %q, want %q", nlri.RD, "10.0.0.1:100")
	}
	if len(nlri.Spec) != 1 {
		t.Fatalf("got %d specs, want 1", len(nlri.Spec))
	}
}

// TestVPNFlowspecNLRI_IPv4_RDType2 validates VPN FlowSpec with RD Type 2 (4-byte AS : 2-byte value).
func TestVPNFlowspecNLRI_IPv4_RDType2(t *testing.T) {
	// RD(8) + Type2 source prefix 192.168.1.0/24 (5 bytes) = 13 total
	input := []byte{
		0x0d, // Length: 13
		// RD Type 2: AS 65536, value 1
		0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		// Type 2: Source Prefix 192.168.1.0/24
		0x02, 0x18, 0xc0, 0xa8, 0x01,
	}
	nlri, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.RD != "65536:1" {
		t.Errorf("RD = %q, want %q", nlri.RD, "65536:1")
	}
	if len(nlri.Spec) != 1 {
		t.Fatalf("got %d specs, want 1", len(nlri.Spec))
	}
}

// TestVPNFlowspecNLRI_IPv6 validates VPN FlowSpec with IPv6 prefix encoding.
func TestVPNFlowspecNLRI_IPv6(t *testing.T) {
	// RD(8) + Type1 IPv6 dest prefix 2001:db8::/32 offset=0
	// IPv6 prefix spec: type(1) + prefixlen(1) + offset(1) + prefix(ceil((32-0)/8)=4) = 7 bytes
	// Total: 8 + 7 = 15
	input := []byte{
		0x0f, // Length: 15
		// RD Type 0: ASN 200, value 300
		0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x01, 0x2c,
		// Type 1: Destination Prefix 2001:db8::/32, offset=0
		0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8,
	}
	nlri, err := UnmarshalVPNFlowspecNLRI(input, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.RD != "200:300" {
		t.Errorf("RD = %q, want %q", nlri.RD, "200:300")
	}
	if nlri.SpecHash == "" {
		t.Error("SpecHash should not be empty")
	}

	// Verify IPv6 VPN produces different hash than IPv4 VPN with same specs
	ipv4Input := []byte{
		0x0e, // Length: 14
		0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x01, 0x2c,
		// IPv4 Type 1: Dest Prefix with same bytes as prefix_len+prefix
		0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8,
	}
	ipv4NLRI, err := UnmarshalVPNFlowspecNLRI(ipv4Input, false)
	if err != nil {
		t.Fatalf("IPv4 parse error: %v", err)
	}
	if nlri.SpecHash == ipv4NLRI.SpecHash {
		t.Error("IPv6 and IPv4 VPN FlowSpec should have different SpecHash")
	}
}

// TestVPNFlowspecNLRI_MultiNLRI validates parsing multiple VPN FlowSpec NLRIs.
func TestVPNFlowspecNLRI_MultiNLRI(t *testing.T) {
	// NLRI 1: RD + Type1 dest prefix 10.0.0.0/8 (3 bytes) = 11
	nlri1 := []byte{
		0x0b, // Length: 11
		// RD Type 0: ASN 100, value 1
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01,
		// Type 1: Dest Prefix 10.0.0.0/8
		0x01, 0x08, 0x0a,
	}
	// NLRI 2: RD + Type2 source prefix 172.16.0.0/16 (4 bytes) = 12
	nlri2 := []byte{
		0x0c, // Length: 12
		// RD Type 0: ASN 200, value 2
		0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x02,
		// Type 2: Source Prefix 172.16.0.0/16
		0x02, 0x10, 0xac, 0x10,
	}
	input := append(nlri1, nlri2...)
	results, err := UnmarshalAllVPNFlowspecNLRI(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d NLRIs, want 2", len(results))
	}
	if results[0].RD != "100:1" {
		t.Errorf("NLRI[0].RD = %q, want %q", results[0].RD, "100:1")
	}
	if results[1].RD != "200:2" {
		t.Errorf("NLRI[1].RD = %q, want %q", results[1].RD, "200:2")
	}
}

// TestVPNFlowspecNLRI_EmptyInput validates withdraw-all behavior.
func TestVPNFlowspecNLRI_EmptyInput(t *testing.T) {
	result, err := UnmarshalAllVPNFlowspecNLRI(nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for empty input, got %v", result)
	}
}

// TestVPNFlowspecNLRI_SingleEmpty validates error for empty single NLRI.
func TestVPNFlowspecNLRI_SingleEmpty(t *testing.T) {
	_, err := UnmarshalVPNFlowspecNLRI(nil, false)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

// TestVPNFlowspecNLRI_ShortRD validates error when payload too short for RD.
func TestVPNFlowspecNLRI_ShortRD(t *testing.T) {
	// Length=4 but need 8 bytes for RD
	input := []byte{0x04, 0x00, 0x00, 0x00, 0x01}
	_, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err == nil {
		t.Fatal("expected error for short RD")
	}
	if !strings.Contains(err.Error(), "Route Distinguisher") {
		t.Errorf("error %q should mention Route Distinguisher", err.Error())
	}
}

// TestVPNFlowspecNLRI_InvalidRDType validates error for invalid RD type.
func TestVPNFlowspecNLRI_InvalidRDType(t *testing.T) {
	// RD(8) + Type1 prefix (3) + Type3 proto (2) = 13
	input := []byte{
		0x0d, // Length: 13
		// RD Type 5 (invalid)
		0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Type 1: Dest Prefix 10.0.0.0/8
		0x01, 0x08, 0x0a,
		0x03, 0x81, 0x06,
	}
	_, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err == nil {
		t.Fatal("expected error for invalid RD type")
	}
	if !strings.Contains(err.Error(), "Route Distinguisher") {
		t.Errorf("error %q should mention Route Distinguisher", err.Error())
	}
}

// TestVPNFlowspecNLRI_MultiSpec validates VPN NLRI with multiple filter specs.
func TestVPNFlowspecNLRI_MultiSpec(t *testing.T) {
	// RD(8) + Type1 dest 10.0.0.0/8 (3 bytes) + Type5 dest port 80 (4 bytes: type+op+2-byte val)
	// = 8 + 3 + 4 = 15
	input := []byte{
		0x0f, // Length: 15
		// RD Type 0: ASN 65000, value 100
		0x00, 0x00, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64,
		// Type 1: Dest Prefix 10.0.0.0/8
		0x01, 0x08, 0x0a,
		// Type 5: Dest Port == 80 (EOL, 2-byte value)
		0x05, 0x91, 0x00, 0x50,
	}
	nlri, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nlri.Spec) != 2 {
		t.Errorf("got %d specs, want 2", len(nlri.Spec))
	}
	if nlri.RD != "65000:100" {
		t.Errorf("RD = %q, want %q", nlri.RD, "65000:100")
	}
}

// TestVPNFlowspecNLRI_ExtendedLength validates 2-byte length encoding.
func TestVPNFlowspecNLRI_ExtendedLength(t *testing.T) {
	// 0xf0 0x0d = length 13 (0x00<<8 | 0x0d)
	input := []byte{
		0xf0, 0x0d, // Extended length: 13
		// RD Type 0: ASN 100, value 200
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
		// Type 1: Destination Prefix 10.0.1.0/24
		0x01, 0x18, 0x0a, 0x00, 0x01,
	}
	nlri, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.RD != "100:200" {
		t.Errorf("RD = %q, want %q", nlri.RD, "100:200")
	}
	if nlri.Length != 13 {
		t.Errorf("Length = %d, want 13", nlri.Length)
	}
}

// TestVPNFlowspecNLRI_TrailingBytes validates single NLRI ignores trailing data.
func TestVPNFlowspecNLRI_TrailingBytes(t *testing.T) {
	input := []byte{
		0x0b, // Length: 11
		// RD Type 0: ASN 1, value 1
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		// Type 1: Dest Prefix 10.0.0.0/8
		0x01, 0x08, 0x0a,
		// Trailing bytes (another NLRI)
		0x0b,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
		0x01, 0x08, 0x0b,
	}
	nlri, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.RD != "1:1" {
		t.Errorf("RD = %q, want %q", nlri.RD, "1:1")
	}
}

// TestVPNFlowspecNLRI_RDOnlyNoSpecs validates VPN NLRI with RD but no specs.
func TestVPNFlowspecNLRI_RDOnlyNoSpecs(t *testing.T) {
	input := []byte{
		0x08, // Length: 8 (RD only, no specs)
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	}
	nlri, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.RD != "1:1" {
		t.Errorf("RD = %q, want %q", nlri.RD, "1:1")
	}
	if len(nlri.Spec) != 0 {
		t.Errorf("expected 0 specs for RD-only NLRI, got %d", len(nlri.Spec))
	}
}

// TestVPNFlowspecNLRI_HashDiffersFromNonVPN validates VPN and non-VPN produce different hashes for same specs.
func TestVPNFlowspecNLRI_HashDiffersFromNonVPN(t *testing.T) {
	// Non-VPN IPv4: Type1 dest prefix 10.0.1.0/24
	nonVPNInput := []byte{
		0x05, // Length: 5
		0x01, 0x18, 0x0a, 0x00, 0x01,
	}
	nonVPN, err := UnmarshalFlowspecNLRI(nonVPNInput)
	if err != nil {
		t.Fatalf("non-VPN parse error: %v", err)
	}

	// VPN IPv4: same specs with RD
	vpnInput := []byte{
		0x0d, // Length: 13 (RD=8 + specs=5)
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
		0x01, 0x18, 0x0a, 0x00, 0x01,
	}
	vpn, err := UnmarshalVPNFlowspecNLRI(vpnInput, false)
	if err != nil {
		t.Fatalf("VPN parse error: %v", err)
	}

	if nonVPN.SpecHash == vpn.SpecHash {
		t.Error("VPN and non-VPN FlowSpec should have different SpecHash values")
	}
}

// TestVPNFlowspecNLRI_ZeroLengthVPN validates error for zero-length VPN NLRI.
func TestVPNFlowspecNLRI_ZeroLengthVPN(t *testing.T) {
	input := []byte{0x00} // Length: 0
	_, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err == nil {
		t.Fatal("expected error for zero-length VPN NLRI")
	}
	if !strings.Contains(err.Error(), "zero-length") {
		t.Errorf("error %q should mention zero-length", err.Error())
	}
}

// TestVPNFlowspecNLRI_ExtendedLengthTooShort validates extended length header with only 1 byte.
func TestVPNFlowspecNLRI_ExtendedLengthTooShort(t *testing.T) {
	input := []byte{0xf0} // Extended length marker but only 1 byte
	_, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err == nil {
		t.Fatal("expected error for truncated extended length")
	}
}

// TestVPNFlowspecNLRI_LengthExceedsBuffer validates length field larger than buffer.
func TestVPNFlowspecNLRI_LengthExceedsBuffer(t *testing.T) {
	input := []byte{0x20, 0x00, 0x00} // Length=32 but only 2 bytes follow
	_, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err == nil {
		t.Fatal("expected error for length exceeding buffer")
	}
}

// TestVPNFlowspecNLRI_AllMultiError validates error in multi-NLRI returns offset.
func TestVPNFlowspecNLRI_AllMultiError(t *testing.T) {
	// First NLRI is valid, second is truncated
	input := []byte{
		// Valid NLRI 1
		0x0b,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x01, 0x08, 0x0a,
		// Truncated NLRI 2: length=20 but not enough bytes
		0x14,
		0x00, 0x00,
	}
	_, err := UnmarshalAllVPNFlowspecNLRI(input, false)
	if err == nil {
		t.Fatal("expected error for truncated second NLRI")
	}
	if !strings.Contains(err.Error(), "offset") {
		t.Errorf("error %q should mention offset", err.Error())
	}
}

// TestVPNFlowspecNLRI_JSON_RoundTrip validates JSON marshaling includes RD field.
func TestVPNFlowspecNLRI_JSON_RoundTrip(t *testing.T) {
	input := []byte{
		0x0d, // Length: 13
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
		0x01, 0x18, 0x0a, 0x00, 0x01,
	}
	nlri, err := UnmarshalVPNFlowspecNLRI(input, false)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// Marshal to JSON
	data, err := json.Marshal(nlri)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// Verify RD field is present in JSON
	jsonStr := string(data)
	if !strings.Contains(jsonStr, `"rd"`) {
		t.Errorf("JSON %s should contain rd field", jsonStr)
	}
	if !strings.Contains(jsonStr, "100:200") {
		t.Errorf("JSON %s should contain RD value 100:200", jsonStr)
	}
}
