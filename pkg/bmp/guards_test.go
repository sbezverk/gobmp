package bmp

import (
	"testing"
)

// TestUnmarshalCommonHeaderGuards covers length guard, version check, and
// unknown message types (RFC 7854 says MUST ignore unknown types).
func TestUnmarshalCommonHeaderGuards(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantErr  bool
		wantType byte
	}{
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "too short (5 bytes, need 6)",
			input:   []byte{0x03, 0x00, 0x00, 0x00, 0x06},
			wantErr: true,
		},
		{
			name:     "valid version 3, RouteMonitor (type=0)",
			input:    []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x00},
			wantErr:  false,
			wantType: RouteMonitorMsg,
		},
		{
			name:     "valid version 3, Termination (type=5)",
			input:    []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x05},
			wantErr:  false,
			wantType: TerminationMsg,
		},
		{
			name:    "invalid version (1)",
			input:   []byte{0x01, 0x00, 0x00, 0x00, 0x06, 0x00},
			wantErr: true,
		},
		{
			name:    "invalid version (2)",
			input:   []byte{0x02, 0x00, 0x00, 0x00, 0x06, 0x00},
			wantErr: true,
		},
		{
			// RFC 7854 §4.1: unknown types MUST be ignored (no error returned)
			name:     "unknown message type (type=7) — no error per RFC 7854",
			input:    []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x07},
			wantErr:  false,
			wantType: 7,
		},
		{
			name:     "unknown message type (type=255) — no error per RFC 7854",
			input:    []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0xFF},
			wantErr:  false,
			wantType: 255,
		},
		{
			name:     "large MessageLength is stored as-is",
			input:    []byte{0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0x04},
			wantErr:  false,
			wantType: InitiationMsg,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalCommonHeader(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalCommonHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.MessageType != tt.wantType {
				t.Errorf("MessageType = %d, want %d", got.MessageType, tt.wantType)
			}
			if got.Version != 3 {
				t.Errorf("Version = %d, want 3", got.Version)
			}
		})
	}
}

// TestUnmarshalPeerDownMessageGuards covers length guards, reason 0 rejection,
// reason code 6 (RFC 9069), and unknown reason codes.
func TestUnmarshalPeerDownMessageGuards(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantErr     bool
		wantReason  uint8
		wantDataLen int
	}{
		{
			name:    "empty input — length guard",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "reason 0 — Reserved, must be rejected",
			input:   []byte{0x00},
			wantErr: true,
		},
		{
			name:        "reason 1 — local system closed BGP (NOTIFICATION PDU follows)",
			input:       []byte{0x01, 0xAA, 0xBB, 0xCC},
			wantErr:     false,
			wantReason:  1,
			wantDataLen: 3,
		},
		{
			name:        "reason 2 — local system closed FSM event",
			input:       []byte{0x02, 0x00, 0x01},
			wantErr:     false,
			wantReason:  2,
			wantDataLen: 2,
		},
		{
			name:        "reason 3 — remote system closed NOTIFICATION PDU follows",
			input:       []byte{0x03, 0x01, 0x02, 0x03},
			wantErr:     false,
			wantReason:  3,
			wantDataLen: 3,
		},
		{
			name:        "reason 4 — remote system closed FSM event",
			input:       []byte{0x04, 0x00, 0x02},
			wantErr:     false,
			wantReason:  4,
			wantDataLen: 2,
		},
		{
			name:        "reason 5 — peer de-configured",
			input:       []byte{0x05},
			wantErr:     false,
			wantReason:  5,
			wantDataLen: 0,
		},
		{
			name: "reason 6 — RFC 9069 Loc-RIB peer down (TLV data follows)",
			input: func() []byte {
				// Reason byte + a simple TLV (type=0, length=3, value="abc")
				b := make([]byte, 1+4+3)
				b[0] = 6
				b[1] = 0x00
				b[2] = 0x00
				b[3] = 0x00
				b[4] = 0x03
				copy(b[5:], []byte("abc"))
				return b
			}(),
			wantErr:     false,
			wantReason:  6,
			wantDataLen: 7,
		},
		{
			name:        "unknown reason 99 — accepted per forward-compatibility",
			input:       []byte{0x63, 0xDE, 0xAD},
			wantErr:     false,
			wantReason:  99,
			wantDataLen: 2,
		},
		{
			name:        "reason 1 with no data after reason byte",
			input:       []byte{0x01},
			wantErr:     false,
			wantReason:  1,
			wantDataLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalPeerDownMessage(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalPeerDownMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.Reason != tt.wantReason {
				t.Errorf("Reason = %d, want %d", got.Reason, tt.wantReason)
			}
			if len(got.Data) != tt.wantDataLen {
				t.Errorf("len(Data) = %d, want %d", len(got.Data), tt.wantDataLen)
			}
		})
	}
}

// TestUnmarshalBMPRawMessageGuards covers the length guard and happy path.
func TestUnmarshalBMPRawMessageGuards(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		wantLen int
	}{
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "too short (5 bytes, need 6)",
			input:   make([]byte, 5),
			wantErr: true,
		},
		{
			name:    "exactly 6 bytes (minimum common header)",
			input:   []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x04},
			wantErr: false,
			wantLen: 6,
		},
		{
			name:    "full message with payload",
			input:   []byte{0x03, 0x00, 0x00, 0x00, 0x0A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD},
			wantErr: false,
			wantLen: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBMPRawMessage(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBMPRawMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got.Msg) != tt.wantLen {
				t.Errorf("len(Msg) = %d, want %d", len(got.Msg), tt.wantLen)
			}
			// Verify copy is independent
			copy(tt.input, make([]byte, len(tt.input)))
			if got.Msg[0] != 0x03 {
				t.Errorf("Msg not a copy — first byte corrupted after input mutation")
			}
		})
	}
}
