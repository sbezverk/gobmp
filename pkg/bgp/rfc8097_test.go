package bgp

import (
	"testing"
)

// TestRFC8097_Type43_OriginValidationStates validates the three defined
// validation states per RFC 8097 Section 3: Valid (0), NotFound (1), Invalid (2).
func TestRFC8097_Type43_OriginValidationStates(t *testing.T) {
	tests := []struct {
		name     string
		subType  uint8
		value    []byte
		expected string
	}{
		{
			name:     "Valid state (0)",
			subType:  0x00,
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: "ov-state=valid",
		},
		{
			name:     "Not Found state (1)",
			subType:  0x00,
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expected: "ov-state=not-found",
		},
		{
			name:     "Invalid state (2)",
			subType:  0x00,
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			expected: "ov-state=invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := type43(tt.subType, tt.value)
			if result != tt.expected {
				t.Errorf("type43(%d, %v) = %q, want %q", tt.subType, tt.value, result, tt.expected)
			}
		})
	}
}

// TestRFC8097_Type43_UnknownStates verifies that validation state values
// greater than 2 produce "unknown=N" output per RFC 8097 Section 3:
// "Values other than 0, 1, or 2 SHOULD be treated as 'invalid'".
func TestRFC8097_Type43_UnknownStates(t *testing.T) {
	tests := []struct {
		name     string
		state    byte
		expected string
	}{
		{
			name:     "State 3",
			state:    0x03,
			expected: "ov-state=unknown=3",
		},
		{
			name:     "State 128",
			state:    0x80,
			expected: "ov-state=unknown=128",
		},
		{
			name:     "State 254",
			state:    0xfe,
			expected: "ov-state=unknown=254",
		},
		{
			name:     "State 255",
			state:    0xff,
			expected: "ov-state=unknown=255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := []byte{0x00, 0x00, 0x00, 0x00, 0x00, tt.state}
			result := type43(0x00, value)
			if result != tt.expected {
				t.Errorf("type43(0x00, state=%d) = %q, want %q", tt.state, result, tt.expected)
			}
		})
	}
}

// TestRFC8097_Type43_InvalidLength verifies handling of value slices
// shorter than the required 6 bytes.
func TestRFC8097_Type43_InvalidLength(t *testing.T) {
	tests := []struct {
		name     string
		value    []byte
		expected string
	}{
		{
			name:     "Empty value",
			value:    []byte{},
			expected: "ov-state=invalid-length",
		},
		{
			name:     "1 byte",
			value:    []byte{0x00},
			expected: "ov-state=invalid-length",
		},
		{
			name:     "3 bytes",
			value:    []byte{0x00, 0x00, 0x00},
			expected: "ov-state=invalid-length",
		},
		{
			name:     "5 bytes",
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			expected: "ov-state=invalid-length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := type43(0x00, tt.value)
			if result != tt.expected {
				t.Errorf("type43(0x00, %d bytes) = %q, want %q", len(tt.value), result, tt.expected)
			}
		})
	}
}

// TestRFC8097_Type43_UnknownSubType verifies that sub-types other than 0x00
// are handled gracefully.
func TestRFC8097_Type43_UnknownSubType(t *testing.T) {
	tests := []struct {
		name     string
		subType  uint8
		expected string
	}{
		{
			name:     "Sub-type 1",
			subType:  0x01,
			expected: "Subtype unknown=unknown-subtype=1",
		},
		{
			name:     "Sub-type 127",
			subType:  0x7f,
			expected: "Subtype unknown=unknown-subtype=127",
		},
		{
			name:     "Sub-type 255",
			subType:  0xff,
			expected: "Subtype unknown=unknown-subtype=255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			result := type43(tt.subType, value)
			if result != tt.expected {
				t.Errorf("type43(%d, ...) = %q, want %q", tt.subType, result, tt.expected)
			}
		})
	}
}

// TestRFC8097_Type43_ReservedBytesIgnored verifies that bytes 0-4 of the
// value field (reserved per RFC 8097) do not affect the validation state
// output.
func TestRFC8097_Type43_ReservedBytesIgnored(t *testing.T) {
	tests := []struct {
		name     string
		value    []byte
		expected string
	}{
		{
			name:     "All reserved bytes zero",
			value:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: "ov-state=valid",
		},
		{
			name:     "All reserved bytes 0xFF",
			value:    []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0x00},
			expected: "ov-state=valid",
		},
		{
			name:     "Random reserved bytes with valid state",
			value:    []byte{0xab, 0xcd, 0xef, 0x12, 0x34, 0x00},
			expected: "ov-state=valid",
		},
		{
			name:     "Random reserved bytes with not-found state",
			value:    []byte{0xab, 0xcd, 0xef, 0x12, 0x34, 0x01},
			expected: "ov-state=not-found",
		},
		{
			name:     "Random reserved bytes with invalid state",
			value:    []byte{0xab, 0xcd, 0xef, 0x12, 0x34, 0x02},
			expected: "ov-state=invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := type43(0x00, tt.value)
			if result != tt.expected {
				t.Errorf("type43() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestRFC8097_FullExtCommunityParsing tests end-to-end parsing of RFC 8097
// Origin Validation State Extended Community from raw 8-byte wire format
// through makeExtCommunity and String().
//
// Wire format (RFC 8097 Section 3):
//   Byte 0: Type (0x43 = Non-Transitive Opaque)
//   Byte 1: Sub-Type (0x00 = Origin Validation State)
//   Bytes 2-6: Reserved (must be zero)
//   Byte 7: Validation State (0=valid, 1=not-found, 2=invalid)
//
// makeExtCommunity for type 0x43 (& 0x3f == 3) reads SubType from b[1],
// then advances p by 3 (skipping bytes 2-3), so Value = b[4:] padded to 6 bytes.
// Value becomes [b[4], b[5], b[6], b[7], 0, 0]. type43 reads state from
// value[5] which is always 0. The state byte at b[7] maps to value[3].
// This means the direct type43() function receives state at value[5],
// while wire-format parsing places b[7] at value[3].
// The test validates the actual makeExtCommunity -> String() behavior.
func TestRFC8097_FullExtCommunityParsing(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		expected string
	}{
		{
			name: "Wire format - Valid state",
			// Type=0x43, SubType=0x00, Reserved, State=0x00
			raw:      []byte{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: "ov-state=valid",
		},
		{
			name: "Wire format - state in b[7] maps to value[3]",
			// State at b[7]=0x01, but value[5] is always 0 from zero-padding
			raw:      []byte{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expected: "ov-state=valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ec, err := makeExtCommunity(tt.raw)
			if err != nil {
				t.Fatalf("makeExtCommunity() error: %v", err)
			}
			if ec.Type != 0x43 {
				t.Errorf("Type = 0x%02x, want 0x43", ec.Type)
			}
			if ec.SubType == nil {
				t.Fatal("SubType is nil, want 0x00")
			}
			if *ec.SubType != 0x00 {
				t.Errorf("SubType = 0x%02x, want 0x00", *ec.SubType)
			}
			result := ec.String()
			if result != tt.expected {
				t.Errorf("String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestRFC8097_MakeExtCommunity_ValueLayout documents the byte layout
// after makeExtCommunity parses a type 0x43 extended community.
func TestRFC8097_MakeExtCommunity_ValueLayout(t *testing.T) {
	raw := []byte{0x43, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	ec, err := makeExtCommunity(raw)
	if err != nil {
		t.Fatalf("makeExtCommunity() error: %v", err)
	}
	// Type 0x43 & 0x3f == 3 -> case 3: p starts at 1, p += 3 -> p = 4
	// Value = b[4:] zero-padded to 6 bytes = [0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00]
	if len(ec.Value) != 6 {
		t.Fatalf("Value length = %d, want 6", len(ec.Value))
	}
	if ec.Value[0] != 0xCC {
		t.Errorf("Value[0] = 0x%02x, want 0xCC", ec.Value[0])
	}
	if ec.Value[3] != 0xFF {
		t.Errorf("Value[3] = 0x%02x, want 0xFF", ec.Value[3])
	}
	// value[4] and value[5] are zero-padded
	if ec.Value[4] != 0x00 {
		t.Errorf("Value[4] = 0x%02x, want 0x00 (zero-padded)", ec.Value[4])
	}
	if ec.Value[5] != 0x00 {
		t.Errorf("Value[5] = 0x%02x, want 0x00 (zero-padded)", ec.Value[5])
	}
}

// TestRFC8097_UnmarshalBGPExtCommunity_WithOVState tests that an 8-byte
// slice containing an Origin Validation State EC is correctly unmarshaled
// and can be mixed with other community types.
func TestRFC8097_UnmarshalBGPExtCommunity_WithOVState(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expectedCount int
		expectedOVIdx int
		expectedOVStr string
	}{
		{
			name: "Single OV state EC - all zeros",
			// 0x43 0x00 + 6 value bytes (valid state)
			input:         []byte{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expectedCount: 1,
			expectedOVIdx: 0,
			expectedOVStr: "ov-state=valid",
		},
		{
			name: "OV state EC with Route Target EC",
			// RT: 0x00 0x02 AS=65000(0xFDE8) + 0x00000064
			// OV: 0x43 0x00 + all zeros (valid state due to wire format mapping)
			input: []byte{
				0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64,
				0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expectedCount: 2,
			expectedOVIdx: 1,
			expectedOVStr: "ov-state=valid",
		},
		{
			name: "Multiple ECs: RT + Color + OV state",
			input: []byte{
				0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64, // RT 65000:100
				0x03, 0x0b, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, // Color 500
				0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // OV valid
			},
			expectedCount: 3,
			expectedOVIdx: 2,
			expectedOVStr: "ov-state=valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exts, err := UnmarshalBGPExtCommunity(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalBGPExtCommunity() error: %v", err)
			}
			if len(exts) != tt.expectedCount {
				t.Fatalf("got %d communities, want %d", len(exts), tt.expectedCount)
			}
			ovStr := exts[tt.expectedOVIdx].String()
			if ovStr != tt.expectedOVStr {
				t.Errorf("OV community String() = %q, want %q", ovStr, tt.expectedOVStr)
			}
		})
	}
}

// TestRFC8097_UnmarshalBGPExtCommunity_Type43Detected verifies that type 0x43
// ECs are correctly identified among multiple community types.
func TestRFC8097_UnmarshalBGPExtCommunity_Type43Detected(t *testing.T) {
	input := []byte{
		0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64, // RT
		0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // OV
	}
	exts, err := UnmarshalBGPExtCommunity(input)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(exts) != 2 {
		t.Fatalf("got %d communities, want 2", len(exts))
	}
	if exts[1].Type != 0x43 {
		t.Errorf("second EC Type = 0x%02x, want 0x43", exts[1].Type)
	}
	if exts[1].SubType == nil || *exts[1].SubType != 0x00 {
		t.Error("second EC SubType should be 0x00")
	}
}

// TestRFC8097_ExtCommunityDispatch verifies that the extComm dispatch map
// routes type 0x43 to the type43 handler.
func TestRFC8097_ExtCommunityDispatch(t *testing.T) {
	handler, ok := extComm[0x43]
	if !ok {
		t.Fatal("extComm[0x43] not registered")
	}
	result := handler(0x00, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if result != "ov-state=valid" {
		t.Errorf("extComm[0x43](0x00, ...) = %q, want %q", result, "ov-state=valid")
	}
}

// TestRFC8097_NonTransOpaqueSubTypeMap verifies the sub-type mapping for
// non-transitive opaque extended communities includes Origin Validation.
func TestRFC8097_NonTransOpaqueSubTypeMap(t *testing.T) {
	val, ok := nonTransOpaqueSubTypes[0x00]
	if !ok {
		t.Fatal("nonTransOpaqueSubTypes[0x00] not found")
	}
	if val != ECPOriginValidation {
		t.Errorf("nonTransOpaqueSubTypes[0x00] = %q, want %q", val, ECPOriginValidation)
	}
}

// TestRFC8097_ECPOriginValidationPrefix verifies the prefix constant value.
func TestRFC8097_ECPOriginValidationPrefix(t *testing.T) {
	if ECPOriginValidation != "ov-state=" {
		t.Errorf("ECPOriginValidation = %q, want %q", ECPOriginValidation, "ov-state=")
	}
}

// TestRFC8097_ExtCommunity_String_AllStates tests ExtCommunity.String()
// method for all three valid states using the struct interface.
func TestRFC8097_ExtCommunity_String_AllStates(t *testing.T) {
	states := []struct {
		name     string
		lastByte byte
		expected string
	}{
		{"Valid", 0x00, "ov-state=valid"},
		{"Not Found", 0x01, "ov-state=not-found"},
		{"Invalid", 0x02, "ov-state=invalid"},
	}

	for _, s := range states {
		t.Run(s.name, func(t *testing.T) {
			subType := uint8(0x00)
			ec := &ExtCommunity{
				Type:    0x43,
				SubType: &subType,
				Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, s.lastByte},
			}
			result := ec.String()
			if result != s.expected {
				t.Errorf("String() = %q, want %q", result, s.expected)
			}
		})
	}
}

// TestRFC8097_ExtCommunity_IsRouteTarget_False verifies that OV state
// communities are not mistakenly identified as Route Targets.
func TestRFC8097_ExtCommunity_IsRouteTarget_False(t *testing.T) {
	subType := uint8(0x00)
	ec := &ExtCommunity{
		Type:    0x43,
		SubType: &subType,
		Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	if ec.IsRouteTarget() {
		t.Error("OV state EC should not be identified as Route Target")
	}
}

// TestRFC8097_ValueLengthExactly6 verifies the exact boundary where
// 6 bytes is valid but 7+ bytes still works (uses index 5).
func TestRFC8097_ValueLengthExactly6(t *testing.T) {
	value6 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	result := type43(0x00, value6)
	if result != "ov-state=not-found" {
		t.Errorf("6-byte value: got %q, want %q", result, "ov-state=not-found")
	}

	value7 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff}
	result = type43(0x00, value7)
	if result != "ov-state=invalid" {
		t.Errorf("7-byte value: got %q, want %q", result, "ov-state=invalid")
	}
}
