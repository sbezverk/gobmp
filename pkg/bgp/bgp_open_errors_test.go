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
			wantErrMsg: "too short for Optional Parameters",
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

// TestUnmarshalBGPOpenMessage_RFC9072_Extended verifies the positive (happy) path of RFC 9072
// extended Optional Parameters encoding: OptParamLen==255 + 0xFF sentinel + 2-byte extLen.
func TestUnmarshalBGPOpenMessage_RFC9072_Extended(t *testing.T) {
	// Fixed 13-byte header shared by all sub-cases:
	//   [Length 2B][Type 1B][Version 1B][MyAS 2B][HoldTime 2B][BGPID 4B][OptParamLen 1B]
	// OptParamLen is overwritten to 255 in each case to trigger the RFC 9072 path.
	header := func() []byte {
		return []byte{
			0, 29, // Length (placeholder)
			1,    // Type = 1 (OPEN)
			4,    // Version = 4
			0, 1, // MyAS = 1
			0, 90, // HoldTime = 90
			10, 0, 0, 1, // BGPID = 10.0.0.1
			255, // OptParamLen = 255 → triggers RFC 9072 detection
		}
	}

	t.Run("extLen=0 empty body", func(t *testing.T) {
		// RFC 9072 framing: 0xFF sentinel + 2-byte extLen=0 → no TLVs.
		b := header()
		b = append(b,
			0xFF,       // Non-Ext OP Type sentinel
			0x00, 0x00, // Extended Opt. Parm. Length = 0
		)
		msg, err := UnmarshalBGPOpenMessage(b)
		if err != nil {
			t.Fatalf("extLen=0: unexpected error: %v", err)
		}
		if msg == nil {
			t.Fatal("extLen=0: got nil OpenMessage")
		}
		if len(msg.OptionalParameters) != 0 {
			t.Errorf("extLen=0: expected 0 optional parameters, got %d", len(msg.OptionalParameters))
		}
		if len(msg.Capabilities) != 0 {
			t.Errorf("extLen=0: expected 0 capabilities, got %d", len(msg.Capabilities))
		}
	})

	t.Run("extLen with 4-byte AS capability (code 65)", func(t *testing.T) {
		// RFC 9072 TLV format (extended): [Type 1B][Length 2B][Value NB]
		//
		// Capability container TLV (type=2, length=6):
		//   0x02               – Opt. Param. Type = Capabilities (2)
		//   0x00, 0x06         – 2-byte length = 6
		//   0x41               – Capability Code 65 (4-byte AS)
		//   0x04               – Capability Data Length = 4
		//   0x00, 0x00, 0x00, 0x01 – AS4 = 1
		capTLV := []byte{
			0x02, 0x00, 0x06, // type=2, ext-len=6
			0x41, 0x04, 0x00, 0x00, 0x00, 0x01, // cap 65, len 4, AS4=1
		}
		extLen := uint16(len(capTLV)) // = 9

		b := header()
		b = append(b, 0xFF)                          // sentinel
		b = append(b, byte(extLen>>8), byte(extLen)) // 2-byte extLen
		b = append(b, capTLV...)

		msg, err := UnmarshalBGPOpenMessage(b)
		if err != nil {
			t.Fatalf("cap65: unexpected error: %v", err)
		}
		if msg == nil {
			t.Fatal("cap65: got nil OpenMessage")
		}
		as4, capable := msg.Is4BytesASCapable()
		if !capable {
			t.Error("cap65: Is4BytesASCapable() = false, want true")
		}
		if as4 != 1 {
			t.Errorf("cap65: 4-byte AS = %d, want 1", as4)
		}
	})
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
