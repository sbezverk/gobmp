package bmp

import (
	"testing"
)

func TestUnmarshalCommonHeader_ShortMessageLength(t *testing.T) {
	// Valid 6-byte header with version 3 but MessageLength set to 5,
	// which is less than CommonHeaderLength (6). The function must
	// reject this with an appropriate error.
	input := []byte{
		0x03,                   // version 3
		0x00, 0x00, 0x00, 0x05, // MessageLength = 5 (< CommonHeaderLength)
		0x00,                   // message type
	}
	ch, err := UnmarshalCommonHeader(input)
	if err == nil {
		t.Fatal("expected error for MessageLength < CommonHeaderLength, got nil")
	}
	if ch != nil {
		t.Fatalf("expected nil CommonHeader, got %+v", ch)
	}
	want := "bmp: message length 5 is less than minimum 6"
	if err.Error() != want {
		t.Fatalf("unexpected error message: got %q, want %q", err.Error(), want)
	}
}
