package bgp

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalNotificationMessage(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *NotificationMessage
		fail   bool
	}{
		{
			name:  "valid",
			input: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x15, 3, 4, 0},
			expect: &NotificationMessage{
				Length:       21,
				Type:         3,
				ErrorCode:    4,
				ErrorSubCode: 0,
			},
			fail: false,
		},
		{
			name:  "invalid",
			input: []byte{0, 21, 2, 4, 0},
			expect: &NotificationMessage{
				Length:       21,
				Type:         2,
				ErrorCode:    4,
				ErrorSubCode: 0,
			},
			fail: true,
		},
		{
			name:  "valid with data",
			input: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x18, 3, 4, 0, 10, 24, 0},
			expect: &NotificationMessage{
				Length:       24,
				Type:         3,
				ErrorCode:    4,
				ErrorSubCode: 0,
				Data:         []byte{10, 24, 0},
			},
			fail: false,
		},
		{
			name:  "admit shutdown",
			input: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x15, 0x03, 0x06, 0x02},
			expect: &NotificationMessage{
				Length:       21,
				Type:         3,
				ErrorCode:    6,
				ErrorSubCode: 2,
			},
			fail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := UnmarshalBGPNotificationMessage(tt.input)
			if err != nil {
				if !tt.fail {
					t.Fatalf("%v expected to succeed but failed with err:%v", tt.name, err)
				}
			}
			if err == nil {
				if tt.fail {
					t.Fatalf("%v expected to fail but succeeded", tt.name)
				}
				if !reflect.DeepEqual(message, tt.expect) {
					t.Error("unmarshaled and expected messages do not much")
					t.Errorf("Diffs: %+v", deep.Equal(message, tt.expect))
				}
			}
		})
	}
}
