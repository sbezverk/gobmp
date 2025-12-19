package bgp

import (
	"encoding/binary"
	"testing"
)

func TestUnmarshalAIGP_ValidType1TLV(t *testing.T) {
	// Create AIGP with Type 1 (AIGP Metric) TLV
	// Type=1, Length=11 (3 header + 8 value), Value=12345
	b := make([]byte, 11)
	b[0] = 1                                   // Type: AIGP Metric
	binary.BigEndian.PutUint16(b[1:3], 11)     // Length: 11
	binary.BigEndian.PutUint64(b[3:11], 12345) // Metric Value: 12345

	aigp, err := UnmarshalAIGP(b)
	if err != nil {
		t.Fatalf("UnmarshalAIGP failed: %v", err)
	}

	if len(aigp.TLVs) != 1 {
		t.Fatalf("Expected 1 TLV, got %d", len(aigp.TLVs))
	}

	tlv := aigp.TLVs[0]
	if tlv.Type != 1 {
		t.Errorf("Expected Type 1, got %d", tlv.Type)
	}
	if tlv.Length != 11 {
		t.Errorf("Expected Length 11, got %d", tlv.Length)
	}
	if tlv.Value != 12345 {
		t.Errorf("Expected Value 12345, got %d", tlv.Value)
	}
}

func TestUnmarshalAIGP_MultipleTLVs(t *testing.T) {
	// Create AIGP with multiple TLVs
	b := make([]byte, 0)

	// First TLV: Type 1, Value=1000
	tlv1 := make([]byte, 11)
	tlv1[0] = 1
	binary.BigEndian.PutUint16(tlv1[1:3], 11)
	binary.BigEndian.PutUint64(tlv1[3:11], 1000)
	b = append(b, tlv1...)

	// Second TLV: Type 1, Value=2000
	tlv2 := make([]byte, 11)
	tlv2[0] = 1
	binary.BigEndian.PutUint16(tlv2[1:3], 11)
	binary.BigEndian.PutUint64(tlv2[3:11], 2000)
	b = append(b, tlv2...)

	aigp, err := UnmarshalAIGP(b)
	if err != nil {
		t.Fatalf("UnmarshalAIGP failed: %v", err)
	}

	if len(aigp.TLVs) != 2 {
		t.Fatalf("Expected 2 TLVs, got %d", len(aigp.TLVs))
	}

	if aigp.TLVs[0].Value != 1000 {
		t.Errorf("Expected first TLV value 1000, got %d", aigp.TLVs[0].Value)
	}
	if aigp.TLVs[1].Value != 2000 {
		t.Errorf("Expected second TLV value 2000, got %d", aigp.TLVs[1].Value)
	}
}

func TestUnmarshalAIGP_UnknownTLVType(t *testing.T) {
	// Create AIGP with unknown TLV type (Type 255)
	// Should skip the TLV gracefully
	b := make([]byte, 10)
	b[0] = 255                             // Unknown Type
	binary.BigEndian.PutUint16(b[1:3], 10) // Length: 10
	// 7 bytes of data
	for i := 3; i < 10; i++ {
		b[i] = 0xFF
	}

	aigp, err := UnmarshalAIGP(b)
	if err != nil {
		t.Fatalf("UnmarshalAIGP failed: %v", err)
	}

	if len(aigp.TLVs) != 1 {
		t.Fatalf("Expected 1 TLV, got %d", len(aigp.TLVs))
	}

	if aigp.TLVs[0].Type != 255 {
		t.Errorf("Expected Type 255, got %d", aigp.TLVs[0].Type)
	}
}

func TestUnmarshalAIGP_InvalidLength(t *testing.T) {
	// AIGP too short (less than 3 bytes)
	b := []byte{0x01, 0x00}

	_, err := UnmarshalAIGP(b)
	if err == nil {
		t.Fatal("Expected error for invalid length, got nil")
	}
}

func TestUnmarshalAIGP_InvalidMetricTLVLength(t *testing.T) {
	// Type 1 TLV with insufficient data for metric value
	b := make([]byte, 8)
	b[0] = 1                               // Type: AIGP Metric
	binary.BigEndian.PutUint16(b[1:3], 11) // Length: 11 (but only 8 bytes provided)
	// Only 5 bytes of data instead of 8

	_, err := UnmarshalAIGP(b)
	if err == nil {
		t.Fatal("Expected error for invalid metric TLV length, got nil")
	}
}

func TestUnmarshalAIGP_EmptyAIGP(t *testing.T) {
	// Empty AIGP (no TLVs) - should return error
	b := []byte{}

	_, err := UnmarshalAIGP(b)
	if err == nil {
		t.Fatal("Expected error for empty AIGP, got nil")
	}
}

func TestUnmarshalAIGP_TLVWithInvalidLength(t *testing.T) {
	// TLV with length that exceeds available data
	b := make([]byte, 10)
	b[0] = 255                              // Type: Unknown
	binary.BigEndian.PutUint16(b[1:3], 100) // Length: 100 (but only 10 bytes total)

	_, err := UnmarshalAIGP(b)
	if err == nil {
		t.Fatal("Expected error for TLV with invalid length, got nil")
	}
}

func TestUnmarshalAIGP_LargeMetricValue(t *testing.T) {
	// Test with maximum uint64 value
	b := make([]byte, 11)
	b[0] = 1
	binary.BigEndian.PutUint16(b[1:3], 11)
	binary.BigEndian.PutUint64(b[3:11], 0xFFFFFFFFFFFFFFFF)

	aigp, err := UnmarshalAIGP(b)
	if err != nil {
		t.Fatalf("UnmarshalAIGP failed: %v", err)
	}

	if aigp.TLVs[0].Value != 0xFFFFFFFFFFFFFFFF {
		t.Errorf("Expected max uint64 value, got %d", aigp.TLVs[0].Value)
	}
}

func TestUnmarshalAIGP_ZeroMetricValue(t *testing.T) {
	// Test with zero metric value
	b := make([]byte, 11)
	b[0] = 1
	binary.BigEndian.PutUint16(b[1:3], 11)
	binary.BigEndian.PutUint64(b[3:11], 0)

	aigp, err := UnmarshalAIGP(b)
	if err != nil {
		t.Fatalf("UnmarshalAIGP failed: %v", err)
	}

	if aigp.TLVs[0].Value != 0 {
		t.Errorf("Expected Value 0, got %d", aigp.TLVs[0].Value)
	}
}

func TestUnmarshalAIGP_MixedTLVTypes(t *testing.T) {
	// Mix of known (Type 1) and unknown types
	b := make([]byte, 0)

	// Type 1 TLV
	tlv1 := make([]byte, 11)
	tlv1[0] = 1
	binary.BigEndian.PutUint16(tlv1[1:3], 11)
	binary.BigEndian.PutUint64(tlv1[3:11], 5000)
	b = append(b, tlv1...)

	// Unknown Type 10 TLV
	tlv2 := make([]byte, 8)
	tlv2[0] = 10
	binary.BigEndian.PutUint16(tlv2[1:3], 8)
	for i := 3; i < 8; i++ {
		tlv2[i] = 0xAA
	}
	b = append(b, tlv2...)

	aigp, err := UnmarshalAIGP(b)
	if err != nil {
		t.Fatalf("UnmarshalAIGP failed: %v", err)
	}

	if len(aigp.TLVs) != 2 {
		t.Fatalf("Expected 2 TLVs, got %d", len(aigp.TLVs))
	}

	if aigp.TLVs[0].Type != 1 || aigp.TLVs[0].Value != 5000 {
		t.Errorf("First TLV incorrect: Type=%d, Value=%d", aigp.TLVs[0].Type, aigp.TLVs[0].Value)
	}
	if aigp.TLVs[1].Type != 10 {
		t.Errorf("Second TLV incorrect: Type=%d", aigp.TLVs[1].Type)
	}
}

func TestBaseAttributes_AIGPIntegration(t *testing.T) {
	// Test AIGP field in BaseAttributes structure
	ba := &BaseAttributes{}

	// Create AIGP
	aigpData := make([]byte, 11)
	aigpData[0] = 1
	binary.BigEndian.PutUint16(aigpData[1:3], 11)
	binary.BigEndian.PutUint64(aigpData[3:11], 99999)

	aigp, err := UnmarshalAIGP(aigpData)
	if err != nil {
		t.Fatalf("Failed to create AIGP: %v", err)
	}

	ba.AIGP = aigp

	if ba.AIGP == nil {
		t.Fatal("AIGP field is nil")
	}
	if len(ba.AIGP.TLVs) != 1 {
		t.Fatalf("Expected 1 TLV in BaseAttributes.AIGP, got %d", len(ba.AIGP.TLVs))
	}
	if ba.AIGP.TLVs[0].Value != 99999 {
		t.Errorf("Expected AIGP value 99999, got %d", ba.AIGP.TLVs[0].Value)
	}
}
