package validator

import (
	"bytes"
	"testing"
)

func TestStoredMessage_MarshalUnmarshal_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		topicType uint32
		message   []byte
	}{
		{
			name:      "unicast prefix message",
			topicType: 1,
			message:   []byte(`{"prefix":"10.0.0.0","prefix_len":24}`),
		},
		{
			name:      "empty message",
			topicType: 5,
			message:   []byte{},
		},
		{
			name:      "binary message payload",
			topicType: 12,
			message:   []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := &StoredMessage{
				TopicType: tt.topicType,
				Len:       uint32(len(tt.message)),
				Message:   tt.message,
			}

			marshaled := orig.Marshal()

			got := &StoredMessage{}
			if err := got.Unmarshal(marshaled); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}

			if got.TopicType != orig.TopicType {
				t.Errorf("TopicType = %d, want %d", got.TopicType, orig.TopicType)
			}
			if got.Len != orig.Len {
				t.Errorf("Len = %d, want %d", got.Len, orig.Len)
			}
			if !bytes.Equal(got.Message, orig.Message) {
				t.Errorf("Message = %v, want %v", got.Message, orig.Message)
			}
		})
	}
}

func TestStoredMessage_Unmarshal_ErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "too short for header",
			input: []byte{0x00, 0x00, 0x00},
		},
		{
			name:  "message length exceeds buffer",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := &StoredMessage{}
			if err := sm.Unmarshal(tt.input); err == nil {
				t.Errorf("Unmarshal() expected error for input %v, got nil", tt.input)
			}
		})
	}
}
