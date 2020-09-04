package bmp

import (
	"reflect"
	"testing"
)

func TestPerPeerHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		original *PerPeerHeader
		fail     bool
	}{
		{
			name: "Valid Per Peer Header",
			original: &PerPeerHeader{
				PeerType: 0,
			},
			fail: false,
		},
		{
			name: "Invalid Per Peer Header ",
			original: &PerPeerHeader{
				PeerType: 4,
			},
			fail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.original.Serialize()
			if err != nil {
				t.Fatalf("failed to serialize original common header with error: %+v", err)
			}
			result, err := UnmarshalPerPeerHeader(b)
			if err != nil && !tt.fail {
				t.Fatalf("supposed to succeed but fail with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatalf("supposed to fail but succeeded")
			}
			if !tt.fail {
				if !reflect.DeepEqual(tt.original, result) {
					t.Fatalf("Original: %+v and Resulting: %+v Per Peer Header do not match.", tt.original, result)
				}
			}
		})
	}
}
