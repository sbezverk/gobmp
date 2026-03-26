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
