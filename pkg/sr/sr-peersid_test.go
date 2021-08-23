package sr

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalPeerSID(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *PeerSID
	}{
		{
			name:  "issue 171",
			input: []byte{0xD0, 0x00, 0x00, 0x00, 0x00, 0x3A, 0xA8},
			expect: &PeerSID{
				Flags: &PeerFlags{
					VFlag: true,
					LFlag: true,
					PFlag: true,
				},
				Weight: 0,
				SID:    15016,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := UnmarshalPeerSID(tt.input)
			if err != nil {
				t.Fatalf("failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, r) {
				t.Logf("Diffs: %+v", deep.Equal(tt.expect, r))
				t.Fatalf("expected peer sid %+v does not match to he actual %+v", tt.expect, r)
			}
			if err == nil {
				t.Logf("Peer SID: %s", r)
			}
		})
	}
}
