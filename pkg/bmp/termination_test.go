package bmp

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestUnmarshalTerminationMessage(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		wantErr       bool
		wantHasReason bool
		wantReason    uint16
		wantStrings   []string
	}{
		{
			name:          "empty body — no TLVs",
			input:         []byte{},
			wantErr:       false,
			wantHasReason: false,
			wantStrings:   nil,
		},
		{
			name: "reason TLV only — AdminClosed (0)",
			input: func() []byte {
				b := make([]byte, 4+2)
				binary.BigEndian.PutUint16(b[0:], 1) // type=1 Reason
				binary.BigEndian.PutUint16(b[2:], 2) // length=2
				binary.BigEndian.PutUint16(b[4:], TermReasonAdminClosed)
				return b
			}(),
			wantErr:       false,
			wantHasReason: true,
			wantReason:    TermReasonAdminClosed,
		},
		{
			name: "reason TLV — Unspecified (1)",
			input: func() []byte {
				b := make([]byte, 4+2)
				binary.BigEndian.PutUint16(b[0:], 1)
				binary.BigEndian.PutUint16(b[2:], 2)
				binary.BigEndian.PutUint16(b[4:], TermReasonUnspecified)
				return b
			}(),
			wantErr:       false,
			wantHasReason: true,
			wantReason:    TermReasonUnspecified,
		},
		{
			name: "reason TLV — OutOfResources (2)",
			input: func() []byte {
				b := make([]byte, 4+2)
				binary.BigEndian.PutUint16(b[0:], 1)
				binary.BigEndian.PutUint16(b[2:], 2)
				binary.BigEndian.PutUint16(b[4:], TermReasonOutOfResources)
				return b
			}(),
			wantErr:       false,
			wantHasReason: true,
			wantReason:    TermReasonOutOfResources,
		},
		{
			name: "reason TLV — Redundant (3)",
			input: func() []byte {
				b := make([]byte, 4+2)
				binary.BigEndian.PutUint16(b[0:], 1)
				binary.BigEndian.PutUint16(b[2:], 2)
				binary.BigEndian.PutUint16(b[4:], TermReasonRedundant)
				return b
			}(),
			wantErr:       false,
			wantHasReason: true,
			wantReason:    TermReasonRedundant,
		},
		{
			name: "reason TLV — PermAdminClosed (4)",
			input: func() []byte {
				b := make([]byte, 4+2)
				binary.BigEndian.PutUint16(b[0:], 1)
				binary.BigEndian.PutUint16(b[2:], 2)
				binary.BigEndian.PutUint16(b[4:], TermReasonPermAdminClosed)
				return b
			}(),
			wantErr:       false,
			wantHasReason: true,
			wantReason:    TermReasonPermAdminClosed,
		},
		{
			name: "string TLV only",
			input: func() []byte {
				msg := []byte("going down for maintenance")
				b := make([]byte, 4+len(msg))
				binary.BigEndian.PutUint16(b[0:], 0) // type=0 String
				binary.BigEndian.PutUint16(b[2:], uint16(len(msg)))
				copy(b[4:], msg)
				return b
			}(),
			wantErr:       false,
			wantHasReason: false,
			wantStrings:   []string{"going down for maintenance"},
		},
		{
			name: "string TLV followed by reason TLV",
			input: func() []byte {
				msg := []byte("planned move")
				b := make([]byte, 4+len(msg)+4+2)
				binary.BigEndian.PutUint16(b[0:], 0)
				binary.BigEndian.PutUint16(b[2:], uint16(len(msg)))
				copy(b[4:], msg)
				off := 4 + len(msg)
				binary.BigEndian.PutUint16(b[off:], 1)
				binary.BigEndian.PutUint16(b[off+2:], 2)
				binary.BigEndian.PutUint16(b[off+4:], TermReasonAdminClosed)
				return b
			}(),
			wantErr:       false,
			wantHasReason: true,
			wantReason:    TermReasonAdminClosed,
			wantStrings:   []string{"planned move"},
		},
		{
			name: "two string TLVs",
			input: func() []byte {
				msg1 := []byte("reason A")
				msg2 := []byte("reason B")
				b := make([]byte, 4+len(msg1)+4+len(msg2))
				binary.BigEndian.PutUint16(b[0:], 0)
				binary.BigEndian.PutUint16(b[2:], uint16(len(msg1)))
				copy(b[4:], msg1)
				off := 4 + len(msg1)
				binary.BigEndian.PutUint16(b[off:], 0)
				binary.BigEndian.PutUint16(b[off+2:], uint16(len(msg2)))
				copy(b[off+4:], msg2)
				return b
			}(),
			wantErr:       false,
			wantHasReason: false,
			wantStrings:   []string{"reason A", "reason B"},
		},
		{
			name: "unknown TLV type is silently skipped",
			input: func() []byte {
				b := make([]byte, 4+3)
				binary.BigEndian.PutUint16(b[0:], 99) // unknown
				binary.BigEndian.PutUint16(b[2:], 3)
				copy(b[4:], []byte("ext"))
				return b
			}(),
			wantErr:       false,
			wantHasReason: false,
		},
		{
			name: "reason TLV value too short (1 byte)",
			input: func() []byte {
				b := make([]byte, 4+1)
				binary.BigEndian.PutUint16(b[0:], 1)
				binary.BigEndian.PutUint16(b[2:], 1) // length=1, but reason needs 2
				b[4] = 0x00
				return b
			}(),
			wantErr: true,
		},
		{
			name:    "truncated TLV header",
			input:   []byte{0x00, 0x01, 0x00}, // only 3 bytes, need 4 for header
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalTerminationMessage(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalTerminationMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.HasReason != tt.wantHasReason {
				t.Errorf("HasReason = %v, want %v", got.HasReason, tt.wantHasReason)
			}
			if tt.wantHasReason && got.Reason != tt.wantReason {
				t.Errorf("Reason = %d, want %d", got.Reason, tt.wantReason)
			}
			if len(tt.wantStrings) > 0 {
				if len(got.Strings) != len(tt.wantStrings) {
					t.Fatalf("Strings count = %d, want %d", len(got.Strings), len(tt.wantStrings))
				}
				for i, s := range tt.wantStrings {
					if got.Strings[i] != s {
						t.Errorf("Strings[%d] = %q, want %q", i, got.Strings[i], s)
					}
				}
			}
		})
	}
}

func TestReasonString(t *testing.T) {
	tests := []struct {
		name      string
		tm        TerminationMessage
		wantSubst string // substring that must appear in result
	}{
		{
			name:      "no reason TLV",
			tm:        TerminationMessage{HasReason: false},
			wantSubst: "no reason",
		},
		{
			name:      "AdminClosed",
			tm:        TerminationMessage{HasReason: true, Reason: TermReasonAdminClosed},
			wantSubst: "administratively closed",
		},
		{
			name:      "Unspecified",
			tm:        TerminationMessage{HasReason: true, Reason: TermReasonUnspecified},
			wantSubst: "unspecified",
		},
		{
			name:      "OutOfResources",
			tm:        TerminationMessage{HasReason: true, Reason: TermReasonOutOfResources},
			wantSubst: "out of resources",
		},
		{
			name:      "Redundant",
			tm:        TerminationMessage{HasReason: true, Reason: TermReasonRedundant},
			wantSubst: "redundant",
		},
		{
			name:      "PermAdminClosed",
			tm:        TerminationMessage{HasReason: true, Reason: TermReasonPermAdminClosed},
			wantSubst: "permanently",
		},
		{
			name:      "unknown reason code",
			tm:        TerminationMessage{HasReason: true, Reason: 9999},
			wantSubst: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tm.ReasonString()
			if got == "" {
				t.Fatalf("ReasonString() returned empty string")
			}
			// Basic check: result contains expected substring
			if !strings.Contains(got, tt.wantSubst) {
				t.Errorf("ReasonString() = %q, want substring %q", got, tt.wantSubst)
			}
		})
	}
}
