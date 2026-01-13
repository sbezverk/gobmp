package bmp

import (
	"bytes"
	"testing"
)

// TestUnmarshalBMPRawMessage_Valid tests unmarshaling valid BMP messages
func TestUnmarshalBMPRawMessage_Valid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "minimum valid message (CommonHeaderLength)",
			data: []byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x00}, // version 3, length 6, type 0
		},
		{
			name: "small message",
			data: []byte{0x03, 0x00, 0x00, 0x00, 0x0A, 0x01, 0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name: "medium message (100 bytes)",
			data: make([]byte, 100),
		},
		{
			name: "large message (1000 bytes)",
			data: make([]byte, 1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up common header if needed
			if len(tt.data) >= CommonHeaderLength && tt.data[0] == 0 {
				tt.data[0] = 0x03 // version
				tt.data[4] = byte(len(tt.data) >> 8)
				tt.data[5] = byte(len(tt.data))
			}

			rm, err := UnmarshalBMPRawMessage(tt.data)
			if err != nil {
				t.Errorf("UnmarshalBMPRawMessage() error = %v, want nil", err)
				return
			}

			if rm == nil {
				t.Error("UnmarshalBMPRawMessage() returned nil")
				return
			}

			if len(rm.Msg) != len(tt.data) {
				t.Errorf("Message length = %d, want %d", len(rm.Msg), len(tt.data))
			}

			if !bytes.Equal(rm.Msg, tt.data) {
				t.Error("Message content does not match input data")
			}
		})
	}
}

// TestUnmarshalBMPRawMessage_TooShort tests messages shorter than CommonHeaderLength
func TestUnmarshalBMPRawMessage_TooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty message",
			data: []byte{},
		},
		{
			name: "1 byte",
			data: []byte{0x03},
		},
		{
			name: "5 bytes (one short)",
			data: []byte{0x03, 0x00, 0x00, 0x00, 0x05},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm, err := UnmarshalBMPRawMessage(tt.data)
			if err == nil {
				t.Error("UnmarshalBMPRawMessage() expected error for short message, got nil")
			}
			if rm != nil {
				t.Error("UnmarshalBMPRawMessage() should return nil on error")
			}
		})
	}
}

// TestUnmarshalBMPRawMessage_DataIsolation tests that modifications to input don't affect output
func TestUnmarshalBMPRawMessage_DataIsolation(t *testing.T) {
	original := []byte{0x03, 0x00, 0x00, 0x00, 0x08, 0x01, 0xAA, 0xBB}
	input := make([]byte, len(original))
	copy(input, original)

	rm, err := UnmarshalBMPRawMessage(input)
	if err != nil {
		t.Fatalf("UnmarshalBMPRawMessage() error = %v", err)
	}

	// Modify input after unmarshal
	input[6] = 0xFF
	input[7] = 0xFF

	// Verify raw message was not affected
	if !bytes.Equal(rm.Msg, original) {
		t.Error("Message was affected by input modification - data not properly isolated")
	}
}

// TestUnmarshalBMPRawMessage_AllMessageTypes tests different BMP message types
func TestUnmarshalBMPRawMessage_AllMessageTypes(t *testing.T) {
	messageTypes := []struct {
		name    string
		msgType byte
	}{
		{"RouteMonitor", RouteMonitorMsg},
		{"StatsReport", StatsReportMsg},
		{"PeerDown", PeerDownMsg},
		{"PeerUp", PeerUpMsg},
		{"Initiation", InitiationMsg},
		{"Termination", TerminationMsg},
		{"RouteMirror", RouteMirrorMsg},
	}

	for _, mt := range messageTypes {
		t.Run(mt.name, func(t *testing.T) {
			data := []byte{0x03, 0x00, 0x00, 0x00, 0x06, mt.msgType}

			rm, err := UnmarshalBMPRawMessage(data)
			if err != nil {
				t.Errorf("UnmarshalBMPRawMessage() error = %v for message type %d", err, mt.msgType)
				return
			}

			if rm.Msg[5] != mt.msgType {
				t.Errorf("Message type = %d, want %d", rm.Msg[5], mt.msgType)
			}
		})
	}
}
