package bgp

import (
	"testing"
)

func TestType43_OriginValidationStates(t *testing.T) {
	tests := []struct {
		name     string
		subType  uint8
		value    []byte
		expected string
	}{
		{
			name:     "Valid State (0)",
			subType:  0x00,
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Last byte = 0
			expected: "ov-state=valid",
		},
		{
			name:     "Not Found State (1)",
			subType:  0x00,
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // Last byte = 1
			expected: "ov-state=not-found",
		},
		{
			name:     "Invalid State (2)",
			subType:  0x00,
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, // Last byte = 2
			expected: "ov-state=invalid",
		},
		{
			name:     "Unknown State (3)",
			subType:  0x00,
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, // Last byte = 3
			expected: "ov-state=unknown=3",
		},
		{
			name:     "Unknown State (255)",
			subType:  0x00,
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xff}, // Last byte = 255
			expected: "ov-state=unknown=255",
		},
		{
			name:     "Invalid Length",
			subType:  0x00,
			value:    []byte{0x00, 0x00, 0x00}, // Too short
			expected: "ov-state=invalid-length",
		},
		{
			name:     "Unknown Subtype",
			subType:  0x01,
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: "Subtype unknown=unknown-subtype=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := type43(tt.subType, tt.value)
			if result != tt.expected {
				t.Errorf("type43() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestType43_RFC8097_Compliance(t *testing.T) {
	// RFC 8097 specifies exact byte structure
	// Byte 0-1: Type/Subtype (0x43, 0x00)
	// Byte 2-3: Reserved (0x00, 0x00)
	// Byte 4-6: Reserved (0x00, 0x00, 0x00)
	// Byte 7: Validation State

	tests := []struct {
		name          string
		fullEC        []byte // Full 8-byte EC
		expectedState string
	}{
		{
			name:          "RFC 8097 Valid State",
			fullEC:        []byte{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expectedState: "valid",
		},
		{
			name:          "RFC 8097 Not Found State",
			fullEC:        []byte{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expectedState: "not-found",
		},
		{
			name:          "RFC 8097 Invalid State",
			fullEC:        []byte{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			expectedState: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract value portion (last 6 bytes) as type43 receives
			value := tt.fullEC[2:]
			result := type43(0x00, value)
			expected := "ov-state=" + tt.expectedState
			if result != expected {
				t.Errorf("type43() = %q, want %q", result, expected)
			}
		})
	}
}

func TestExtCommunity_String_Type43(t *testing.T) {
	tests := []struct {
		name     string
		ec       *ExtCommunity
		expected string
	}{
		{
			name: "Type 0x43 Valid State",
			ec: &ExtCommunity{
				Type:    0x43,
				SubType: uint8Ptr(0x00),
				Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Valid
			},
			expected: "ov-state=valid",
		},
		{
			name: "Type 0x43 Not Found State",
			ec: &ExtCommunity{
				Type:    0x43,
				SubType: uint8Ptr(0x00),
				Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // Not found
			},
			expected: "ov-state=not-found",
		},
		{
			name: "Type 0x43 Invalid State",
			ec: &ExtCommunity{
				Type:    0x43,
				SubType: uint8Ptr(0x00),
				Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, // Invalid
			},
			expected: "ov-state=invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.ec.String()
			if result != tt.expected {
				t.Errorf("ExtCommunity.String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// uint8Ptr is a helper function to create a pointer to a uint8 value
func uint8Ptr(v uint8) *uint8 {
	return &v
}
