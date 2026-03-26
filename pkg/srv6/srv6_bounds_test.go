package srv6

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalSRv6BGPPeerNodeSIDTLV_TooShort(t *testing.T) {
	_, err := UnmarshalSRv6BGPPeerNodeSIDTLV(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestUnmarshalSRv6EndpointBehaviorTLV_TooShort(t *testing.T) {
	_, err := UnmarshalSRv6EndpointBehaviorTLV(make([]byte, 3))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestUnmarshalSIDStructureSubSubTLV_TooShort(t *testing.T) {
	_, err := UnmarshalSIDStructureSubSubTLV(make([]byte, 5))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestUnmarshalInformationSubTLV_TooShort(t *testing.T) {
	_, err := UnmarshalInformationSubTLV(make([]byte, 19))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestUnmarshalSRv6L3ServiceSubTLV_HeaderTruncated(t *testing.T) {
	// Only 2 bytes — need 3 for type+length header
	_, err := UnmarshalSRv6L3ServiceSubTLV([]byte{0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestUnmarshalSRv6L3ServiceSubTLV_ValueTruncated(t *testing.T) {
	// Header says length=20 but only 1 byte of value
	input := []byte{0x01, 0x00, 0x14, 0x00}
	_, err := UnmarshalSRv6L3ServiceSubTLV(input)
	if err == nil {
		t.Fatal("expected error for truncated value")
	}
}

func TestUnmarshalSRv6SIDDescriptor_HeaderTruncated(t *testing.T) {
	// Only 3 bytes — need 4 for type+length header
	_, err := UnmarshalSRv6SIDDescriptor([]byte{0x02, 0x06, 0x00})
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestUnmarshalSRv6SIDDescriptor_ValueTruncated(t *testing.T) {
	// Type=518, length=16 but only 2 bytes of value
	input := []byte{0x02, 0x06, 0x00, 0x10, 0x00, 0x00}
	_, err := UnmarshalSRv6SIDDescriptor(input)
	if err == nil {
		t.Fatal("expected error for truncated value")
	}
}

func TestUnmarshalSRv6SIDNLRI_TooShort(t *testing.T) {
	_, err := UnmarshalSRv6SIDNLRI(make([]byte, 12))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestUnmarshalSRv6SIDNLRI_NodeDescTruncated(t *testing.T) {
	// proto(1) + identifier(8) + node desc header(4) = 13 bytes
	// Set node desc length to 20 so it exceeds the buffer
	input := make([]byte, 14)
	input[0] = 0x03 // Proto
	// Node Descriptor Type at offset 9
	input[9] = 0x01
	input[10] = 0x00
	// Node Descriptor Length = 20 at offset 11, exceeds remaining bytes
	input[11] = 0x00
	input[12] = 0x14
	_, err := UnmarshalSRv6SIDNLRI(input)
	if err == nil {
		t.Fatal("expected error for truncated node descriptor")
	}
}

func TestUnmarshalSRv6LocatorTLV_TooShort(t *testing.T) {
	_, err := UnmarshalSRv6LocatorTLV(make([]byte, 7))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestEndXSIDTLV_UnmarshalJSON_WeightField(t *testing.T) {
	// Verify "weight" key (not "weigh") is read correctly
	input := map[string]interface{}{
		"weight": float64(42),
	}
	b, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	e := &EndXSIDTLV{}
	if err := e.UnmarshalJSON(b); err != nil {
		t.Fatalf("UnmarshalJSON error: %v", err)
	}
	if e.Weight != 42 {
		t.Errorf("Weight = %d, want 42", e.Weight)
	}
}
