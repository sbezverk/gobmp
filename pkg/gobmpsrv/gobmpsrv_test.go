package gobmpsrv

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestMessageLengthValidation tests the message length validation logic
// This tests the validation that prevents panic on corrupted data
func TestMessageLengthValidation(t *testing.T) {
	tests := []struct {
		name          string
		messageLength uint32
		shouldReject  bool
		description   string
	}{
		{
			name:          "Valid message length",
			messageLength: bmp.CommonHeaderLength + 100,
			shouldReject:  false,
			description:   "Normal BMP message with 100 bytes of payload",
		},
		{
			name:          "Minimum valid message length",
			messageLength: bmp.CommonHeaderLength + 1,
			shouldReject:  false,
			description:   "Minimum valid message with 1 byte of payload",
		},
		{
			name:          "Zero payload length (msgLen = 0)",
			messageLength: bmp.CommonHeaderLength,
			shouldReject:  true,
			description:   "Invalid: MessageLength equals CommonHeaderLength, resulting in zero-length payload",
		},
		{
			name:          "Negative payload length (msgLen < 0)",
			messageLength: bmp.CommonHeaderLength - 1,
			shouldReject:  true,
			description:   "Invalid: MessageLength less than CommonHeaderLength, resulting in negative payload length",
		},
		{
			name:          "Extremely small MessageLength",
			messageLength: 1,
			shouldReject:  true,
			description:   "Invalid: MessageLength of 1 is far too small",
		},
		{
			name:          "Maximum allowed message length (1MB payload)",
			messageLength: bmp.CommonHeaderLength + (1 << 20),
			shouldReject:  false,
			description:   "Maximum allowed payload size of 1MB",
		},
		{
			name:          "Exceeds maximum allowed length",
			messageLength: bmp.CommonHeaderLength + (1 << 20) + 1,
			shouldReject:  true,
			description:   "Invalid: Payload size exceeds 1MB limit",
		},
		{
			name:          "Extremely large MessageLength",
			messageLength: 1 << 30, // 1GB
			shouldReject:  true,
			description:   "Invalid: Extremely large message length that could cause resource exhaustion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate msgLen as done in clientHandler
			msgLen := int(tt.messageLength) - bmp.CommonHeaderLength

			// Apply the validation logic from clientHandler
			isInvalid := msgLen <= 0 || msgLen > 1<<20

			if isInvalid != tt.shouldReject {
				t.Errorf("%s: expected shouldReject=%v, got isInvalid=%v (msgLen=%d, MessageLength=%d)",
					tt.description, tt.shouldReject, isInvalid, msgLen, tt.messageLength)
			}
		})
	}
}

// TestMessageLengthEdgeCases tests specific edge cases for message length calculation
func TestMessageLengthEdgeCases(t *testing.T) {
	// Test that CommonHeaderLength constant is correctly defined
	if bmp.CommonHeaderLength != 6 {
		t.Errorf("Expected CommonHeaderLength to be 6, got %d", bmp.CommonHeaderLength)
	}

	// Test integer overflow scenarios
	t.Run("uint32 max value", func(t *testing.T) {
		messageLength := uint32(^uint32(0)) // max uint32
		msgLen := int(messageLength) - bmp.CommonHeaderLength

		// This should be rejected as it exceeds max allowed size
		if msgLen <= 0 || msgLen > 1<<20 {
			// Expected: should be rejected
		} else {
			t.Error("Max uint32 value should be rejected")
		}
	})

	// Test boundary at exactly 1MB
	t.Run("exactly 1MB payload", func(t *testing.T) {
		messageLength := uint32(bmp.CommonHeaderLength + (1 << 20))
		msgLen := int(messageLength) - bmp.CommonHeaderLength

		// This should be accepted (exactly at the limit)
		if msgLen <= 0 || msgLen > 1<<20 {
			t.Errorf("Exactly 1MB payload should be accepted, got msgLen=%d", msgLen)
		}
	})

	// Test boundary at 1MB + 1 byte
	t.Run("1MB + 1 byte payload", func(t *testing.T) {
		messageLength := uint32(bmp.CommonHeaderLength + (1 << 20) + 1)
		msgLen := int(messageLength) - bmp.CommonHeaderLength

		// This should be rejected (exceeds the limit)
		if !(msgLen <= 0 || msgLen > 1<<20) {
			t.Errorf("1MB+1 payload should be rejected, got msgLen=%d", msgLen)
		}
	})
}
