package bmp

import (
	"reflect"
	"testing"
)

func TestCommonHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		original *CommonHeader
		fail     bool
	}{
		{
			name: "Valid Common Header",
			original: &CommonHeader{
				Version:       3,
				MessageLength: 64,
				MessageType:   0,
			},
			fail: false,
		},
		{
			name: "Invalid Common Header",
			original: &CommonHeader{
				Version:       5,
				MessageLength: 64,
				MessageType:   0,
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
			result, err := UnmarshalCommonHeader(b)
			if err != nil && !tt.fail {
				t.Fatalf("supposed to succeed but fail with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatalf("supposed to fail but succeeded")
			}
			if !tt.fail {
				if !reflect.DeepEqual(tt.original, result) {
					t.Fatalf("Original: %+v and Resulting: %+v Common Headers do not match.", tt.original, result)
				}
			}
		})
	}
}
