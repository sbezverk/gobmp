package bgp

import (
	"strings"
	"testing"
)

// TestUnmarshalBGPOpenMessage_ErrorCases exercises all validation error paths
// added in BGP OPEN message processing.
func TestUnmarshalBGPOpenMessage_ErrorCases(t *testing.T) {
	// Helper to build a minimal 13-byte BGP OPEN payload (no marker, no opt params).
	// Layout: [Length 2B][Type 1B][Version 1B][MyAS 2B][HoldTime 2B][BGPID 4B][OptParamLen 1B]
	minValid := func() []byte {
		return []byte{
			0, 29, // Length = 29
			1,    // Type = 1 (OPEN)
			4,    // Version = 4
			0, 1, // MyAS = 1
			0, 90, // HoldTime = 90
			192, 168, 1, 1, // BGPID = 192.168.1.1
			0, // OptParamLen = 0
		}
	}

	tests := []struct {
		name       string
		input      func() []byte
		wantErrMsg string
		wantOK     bool
	}{
		// ----------------------------------------------------------------
		// Length checks
		// ----------------------------------------------------------------
		{
			name: "too short – 12 bytes",
			input: func() []byte {
				b := minValid()
				return b[:12] // one byte short
			},
			wantErrMsg: "invalid",
		},
		// ----------------------------------------------------------------
		// Field value checks
		// ----------------------------------------------------------------
		{
			name: "wrong Type byte (not 1)",
			input: func() []byte {
				b := minValid()
				b[2] = 2
				return b
			},
			wantErrMsg: "invalid message type",
		},
		{
			name: "wrong Version byte (not 4)",
			input: func() []byte {
				b := minValid()
				b[3] = 3
				return b
			},
			wantErrMsg: "invalid message version",
		},
		// ----------------------------------------------------------------
		// HoldTime validation
		// ----------------------------------------------------------------
		{
			name: "HoldTime = 1 (invalid)",
			input: func() []byte {
				b := minValid()
				b[6] = 0
				b[7] = 1
				return b
			},
			wantErrMsg: "invalid Hold Time",
		},
		{
			name: "HoldTime = 2 (invalid)",
			input: func() []byte {
				b := minValid()
				b[6] = 0
				b[7] = 2
				return b
			},
			wantErrMsg: "invalid Hold Time",
		},
		{
			name: "HoldTime = 0 (valid – disabled)",
			input: func() []byte {
				b := minValid()
				b[6] = 0
				b[7] = 0
				return b
			},
			wantOK: true,
		},
		{
			name: "HoldTime = 3 (minimum valid)",
			input: func() []byte {
				b := minValid()
				b[6] = 0
				b[7] = 3
				return b
			},
			wantOK: true,
		},
		{
			name:   "HoldTime = 90 (valid)",
			input:  func() []byte { return minValid() },
			wantOK: true,
		},
		// ----------------------------------------------------------------
		// BGPID validation (RFC 6286)
		// ----------------------------------------------------------------
		{
			name: "BGPID = 0.0.0.0 (invalid)",
			input: func() []byte {
				b := minValid()
				b[8] = 0
				b[9] = 0
				b[10] = 0
				b[11] = 0
				return b
			},
			wantErrMsg: "invalid BGP ID",
		},
		// ----------------------------------------------------------------
		// Optional Parameters length bounds
		// ----------------------------------------------------------------
		{
			name: "OptParamLen exceeds buffer",
			input: func() []byte {
				b := minValid()
				b[12] = 100 // claim 100 bytes but buffer ends here
				return b
			},
			wantErrMsg: "exceeds buffer",
		},
		// ----------------------------------------------------------------
		// RFC 9072 extended header
		// ----------------------------------------------------------------
		{
			name: "RFC 9072 sentinel – too short for extended header",
			input: func() []byte {
				// OptParamLen=255, next byte=255, but only 1 more byte (not the
				// required 2-byte extended length field).
				b := minValid()
				b[12] = 255
				b = append(b, 255) // Non-Ext OP Type marker
				// only 1 byte after the marker — need 2 more for extLen
				return b
			},
			wantErrMsg: "too short for RFC 9072",
		},
		{
			name: "RFC 9072 sentinel – extended length exceeds buffer",
			input: func() []byte {
				// OptParamLen=255, next byte=255, then extLen=1000 (2 bytes) but
				// buffer is only a few bytes long.
				b := minValid()
				b[12] = 255
				b = append(b, 255)    // Non-Ext OP Type
				b = append(b, 3, 232) // extLen = 1000
				return b
			},
			wantErrMsg: "exceeds buffer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := UnmarshalBGPOpenMessage(tt.input())
			if tt.wantOK {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if msg == nil {
					t.Fatal("expected non-nil OpenMessage")
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

// TestUnmarshalBGPOpenMessage_Is4ByteASCapable verifies Is4BytesASCapable helper.
func TestUnmarshalBGPOpenMessage_Is4ByteASCapable(t *testing.T) {
	// The "valid" test case from bgp-open_test.go carries capability 65 (4-byte AS).
	input := []byte{0, 99, 1, 4, 19, 206, 0, 90, 192, 168, 8, 8, 70,
		2, 6, 1, 4, 0, 1, 0, 1,
		2, 6, 1, 4, 0, 1, 0, 4,
		2, 6, 1, 4, 0, 1, 0, 128,
		2, 2, 128, 0,
		2, 2, 2, 0,
		2, 6, 65, 4, 0, 0, 19, 206,
		2, 6, 69, 4, 1, 0, 134, 3,
		2, 20, 5, 18, 0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2}
	msg, err := UnmarshalBGPOpenMessage(input)
	if err != nil {
		t.Fatalf("UnmarshalBGPOpenMessage error: %v", err)
	}
	_, capable := msg.Is4BytesASCapable()
	if !capable {
		t.Error("Is4BytesASCapable() = false, want true")
	}
}
