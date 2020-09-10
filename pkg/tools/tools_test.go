package tools

import (
	"encoding/hex"
	"testing"

	"github.com/go-test/deep"
)

func TestMessageHex(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{
			name:   "common header",
			input:  []byte{3, 0, 0, 0, 32, 4},
			expect: "[ 0x03, 0x00, 0x00, 0x00, 0x20, 0x04 ]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MessageHex(tt.input)
			if diff := deep.Equal(tt.expect, got); diff != nil {
				t.Errorf("%+v", diff)
			}
		})
	}
}

func TestConvertToHex(t *testing.T) {
	for b := 0; b <= 0xff; b++ {
		s := ConvertToHex(byte(b))
		v, _ := hex.DecodeString(s)
		if int(v[0]) != b {
			t.Errorf("original %d and decoded %d values do not match", b, v)
		}
	}
}
