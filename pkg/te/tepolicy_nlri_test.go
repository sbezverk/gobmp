package te

import (
	"testing"
)

// TestUnmarshalTEPolicyNLRI_ValidTLVs tests successful parsing with both mandatory TLVs
func TestUnmarshalTEPolicyNLRI_ValidTLVs(t *testing.T) {
	// Build test data with ProtocolID=9 (SR), 8-byte identifier, and NodeDescriptor with TLVs 512 and 516
	testData := []byte{
		0x09,                   // ProtocolID (SR = 9)
		0x00, 0x00, 0x00, 0x00, // Identifier (8 bytes)
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, // Node Descriptor Type (256 = Local)
		0x00, 0x10, // Node Descriptor Length (16 bytes)
		// TLV 512 (ASN) - 4 bytes value
		0x02, 0x00, // Type 512
		0x00, 0x04, // Length 4
		0x00, 0x00, 0xfd, 0xe8, // ASN 65000
		// TLV 516 (BGP Router ID) - 4 bytes value
		0x02, 0x04, // Type 516
		0x00, 0x04, // Length 4
		0xc0, 0xa8, 0x01, 0x01, // BGP Router ID 192.168.1.1
	}

	nlri, err := UnmarshalTEPolicyNLRI(testData)
	if err != nil {
		t.Fatalf("Expected successful parsing with both TLVs, got error: %v", err)
	}
	if nlri == nil {
		t.Fatal("Expected non-nil NLRI")
	}
	if nlri.HeadEnd == nil {
		t.Fatal("Expected non-nil HeadEnd NodeDescriptor")
	}
	if len(nlri.HeadEnd.SubTLV) != 2 {
		t.Fatalf("Expected 2 SubTLVs, got %d", len(nlri.HeadEnd.SubTLV))
	}
}

// TestUnmarshalTEPolicyNLRI_MissingTLV512 tests error when TLV 512 is missing
func TestUnmarshalTEPolicyNLRI_MissingTLV512(t *testing.T) {
	// Build test data with only TLV 516 (missing TLV 512)
	testData := []byte{
		0x09,                   // ProtocolID (SR = 9)
		0x00, 0x00, 0x00, 0x00, // Identifier (8 bytes)
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, // Node Descriptor Type (256 = Local)
		0x00, 0x08, // Node Descriptor Length (8 bytes - only one TLV)
		// TLV 516 (BGP Router ID) - 4 bytes value
		0x02, 0x04, // Type 516
		0x00, 0x04, // Length 4
		0xc0, 0xa8, 0x01, 0x01, // BGP Router ID 192.168.1.1
	}

	nlri, err := UnmarshalTEPolicyNLRI(testData)
	if err == nil {
		t.Fatal("Expected error for missing TLV 512, but got nil")
	}
	if nlri != nil {
		t.Fatalf("Expected nil NLRI on error, got %+v", nlri)
	}
	expectedErr := "HeadEnd Node Descriptor missing mandatory TLV 512 (ASN)"
	if err.Error() != expectedErr {
		t.Fatalf("Expected error message '%s', got '%s'", expectedErr, err.Error())
	}
}

// TestUnmarshalTEPolicyNLRI_MissingTLV516 tests error when TLV 516 is missing
func TestUnmarshalTEPolicyNLRI_MissingTLV516(t *testing.T) {
	// Build test data with only TLV 512 (missing TLV 516)
	testData := []byte{
		0x09,                   // ProtocolID (SR = 9)
		0x00, 0x00, 0x00, 0x00, // Identifier (8 bytes)
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, // Node Descriptor Type (256 = Local)
		0x00, 0x08, // Node Descriptor Length (8 bytes - only one TLV)
		// TLV 512 (ASN) - 4 bytes value
		0x02, 0x00, // Type 512
		0x00, 0x04, // Length 4
		0x00, 0x00, 0xfd, 0xe8, // ASN 65000
	}

	nlri, err := UnmarshalTEPolicyNLRI(testData)
	if err == nil {
		t.Fatal("Expected error for missing TLV 516, but got nil")
	}
	if nlri != nil {
		t.Fatalf("Expected nil NLRI on error, got %+v", nlri)
	}
	expectedErr := "HeadEnd Node Descriptor missing mandatory TLV 516 (BGP Router ID)"
	if err.Error() != expectedErr {
		t.Fatalf("Expected error message '%s', got '%s'", expectedErr, err.Error())
	}
}

// TestUnmarshalTEPolicyNLRI_MissingBothTLVs tests error when both TLVs are missing
func TestUnmarshalTEPolicyNLRI_MissingBothTLVs(t *testing.T) {
	// Build test data with a different TLV (513 = LS-ID) instead of 512 or 516
	testData := []byte{
		0x09,                   // ProtocolID (SR = 9)
		0x00, 0x00, 0x00, 0x00, // Identifier (8 bytes)
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, // Node Descriptor Type (256 = Local)
		0x00, 0x08, // Node Descriptor Length (8 bytes)
		// TLV 513 (LS-ID) - neither 512 nor 516
		0x02, 0x01, // Type 513
		0x00, 0x04, // Length 4
		0x00, 0x00, 0x00, 0x01, // LS-ID value
	}

	nlri, err := UnmarshalTEPolicyNLRI(testData)
	if err == nil {
		t.Fatal("Expected error for missing both TLVs, but got nil")
	}
	if nlri != nil {
		t.Fatalf("Expected nil NLRI on error, got %+v", nlri)
	}
	// Should fail on first check (TLV 512)
	expectedErr := "HeadEnd Node Descriptor missing mandatory TLV 512 (ASN)"
	if err.Error() != expectedErr {
		t.Fatalf("Expected error message '%s', got '%s'", expectedErr, err.Error())
	}
}
