package bmp

import (
	"reflect"
	"testing"
)

func TestPeerDownMsg(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *PeerDownMessage
	}{
		{
			name:  "real case 1",
			input: []byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x15, 0x03, 0x06, 0x04},
			expect: &PeerDownMessage{
				Reason: 1,
				Data:   []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x15, 0x03, 0x06, 0x04},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peerDown, err := UnmarshalPeerDownMessage(tt.input)
			if err != nil {
				t.Fatalf("failed but supposed to succeed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, peerDown) {
				t.Fatalf("expected %+v does not match unmarshaled %+v", tt.expect, peerDown)
			}
		})
	}
}
