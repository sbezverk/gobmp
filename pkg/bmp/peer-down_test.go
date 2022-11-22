package bmp

import (
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

func TestPeerDownMsg(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *PeerDownMessage
		fail   bool
	}{
		{
			name:  "hold timer expired",
			input: []byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x15, 0x03, 0x04, 0x00},
			expect: &PeerDownMessage{
				Reason: 1,
				Data:   []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x15, 0x03, 0x04, 0x00},
				Notification: &bgp.NotificationMessage{
					Length:       21,
					Type:         0x03,
					ErrorCode:    0x04,
					ErrorSubCode: 0x00,
				},
				Description: "Local system closed, Hold Time Expired",
			},
			fail: false,
		},
		{
			name:  "remote admin shutdown",
			input: []byte{0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x15, 0x03, 0x06, 0x02},
			expect: &PeerDownMessage{
				Reason: 3,
				Data:   []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x15, 0x03, 0x06, 0x02},
				Notification: &bgp.NotificationMessage{
					Length:       21,
					Type:         0x03,
					ErrorCode:    0x06,
					ErrorSubCode: 0x02,
				},
				Description: "Remote system closed, Cease Error, Sub Error:Administrative Shutdown",
			},
			fail: false,
		},
		{
			name:  "undefined reason code 0",
			input: []byte{0x00},
			expect: &PeerDownMessage{
				Reason:      0,
				Data:        []byte{},
				Description: "Invalid Peer Down Reason Code:0",
			},
			fail: false,
		},
		{
			name:  "invalid length",
			input: []byte{0x01, 0x00, 0x06, 0x03, 0x06, 0x04},
			expect: &PeerDownMessage{
				Reason: 1,
				Data:   []byte{0x01, 0x00, 0x06, 0x03, 0x06, 0x04},
				Notification: &bgp.NotificationMessage{
					Length:       6,
					Type:         3,
					ErrorCode:    6,
					ErrorSubCode: 4,
				},
				Description: "Cease Error Unknown Sub Error Code",
			},
			fail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peerDown, err := UnmarshalPeerDownMessage(tt.input)
			if err != nil && !tt.fail {
				t.Fatalf("failed but supposed to succeed with error: %+v\n", err)
			}
			if err == nil && !tt.fail {
				if !reflect.DeepEqual(tt.expect, peerDown) {
					t.Fatalf("expected %+v does not match unmarshaled %+v\n", tt.expect, peerDown)
				}
			}
		})
	}
}
