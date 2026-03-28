package sr

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalSRCapabilitySubTLV_TooShort(t *testing.T) {
	// Need 7 bytes min per iteration (3 range + 2 type + 2 length)
	_, err := UnmarshalSRCapabilitySubTLV([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestUnmarshalSRCapabilitySubTLV_ValueTruncated(t *testing.T) {
	// Valid header (7 bytes) but length field says 4 bytes and only 1 available
	input := []byte{
		0x00, 0x00, 0x01, // Range: 1
		0x04, 0x89, // Type: 1161
		0x00, 0x04, // Length: 4
		0x00, // Only 1 byte of value (need 4)
	}
	_, err := UnmarshalSRCapabilitySubTLV(input)
	if err == nil {
		t.Fatal("expected error for truncated value")
	}
}

func TestUnmarshalSRLocalBlockTLV_TooShort(t *testing.T) {
	_, err := UnmarshalSRLocalBlockTLV([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestUnmarshalSRLocalBlockTLV_ValueTruncated(t *testing.T) {
	input := []byte{
		0x00, 0x00, 0x01, // Range: 1
		0x04, 0x89, // Type: 1161
		0x00, 0x04, // Length: 4
		0x00, // Only 1 byte of value
	}
	_, err := UnmarshalSRLocalBlockTLV(input)
	if err == nil {
		t.Fatal("expected error for truncated value")
	}
}

func TestUnmarshalSRLocalBlock_TooShort(t *testing.T) {
	_, err := UnmarshalSRLocalBlock([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	_, err = UnmarshalSRLocalBlock([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for 1-byte input")
	}
}

func TestUnmarshalSRCapability_TooShort(t *testing.T) {
	_, err := UnmarshalSRCapability([]byte{}, base.ISISL1)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	_, err = UnmarshalSRCapability([]byte{0x00}, base.OSPFv2)
	if err == nil {
		t.Fatal("expected error for 1-byte input")
	}
}

func TestUnmarshalAdjacencySIDTLV_TooShort(t *testing.T) {
	_, err := UnmarshalAdjacencySIDTLV([]byte{}, base.ISISL1)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	_, err = UnmarshalAdjacencySIDTLV([]byte{0x00}, base.OSPFv2)
	if err == nil {
		t.Fatal("expected error for 1-byte input")
	}
}

func TestUnmarshalAdjacencySIDTLV_ValidISIS(t *testing.T) {
	// 7-byte ISIS Adjacency SID: Flags(1)=0x30(V+L) + Weight(1)=10 + Reserved(2) + SID(3)=0x003A41(14913)
	input := []byte{0x30, 0x0A, 0x00, 0x00, 0x00, 0x3A, 0x41}
	result, err := UnmarshalAdjacencySIDTLV(input, base.ISISL1)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if result.Weight != 10 {
		t.Errorf("expected weight 10, got %d", result.Weight)
	}
	if result.SID != 14913 {
		t.Errorf("expected SID 14913, got %d", result.SID)
	}
}

func TestUnmarshalAdjacencySIDTLV_ValidOSPF(t *testing.T) {
	// 8-byte OSPF Adjacency SID: Flags(1)=0x60(V+L) + Weight(1)=5 + Reserved(2) + SID(4)=100000
	input := []byte{0x60, 0x05, 0x00, 0x00, 0x00, 0x01, 0x86, 0xA0}
	result, err := UnmarshalAdjacencySIDTLV(input, base.OSPFv2)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if result.Weight != 5 {
		t.Errorf("expected weight 5, got %d", result.Weight)
	}
	if result.SID != 100000 {
		t.Errorf("expected SID 100000, got %d", result.SID)
	}
}

func TestUnmarshalPrefixSIDTLV_TooShort(t *testing.T) {
	_, err := UnmarshalPrefixSIDTLV([]byte{}, base.ISISL1)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	_, err = UnmarshalPrefixSIDTLV([]byte{0x00}, base.OSPFv2)
	if err == nil {
		t.Fatal("expected error for 1-byte input")
	}
}
