package srpolicy

import (
	"net"
	"reflect"
	"testing"
)

func TestUnmarshalLSNLRI73(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *NLRI73
	}{
		{
			name:  "case 1 SR Policy v4",
			input: []byte{0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x63, 0x0A, 0x00, 0x00, 0x0D},
			expect: &NLRI73{
				Length:        12,
				Distinguisher: 2,
				Color:         99,
				Endpoint:      net.ParseIP("10.0.0.13").To4(),
			},
		},
		{
			name:  "case 2 SR Policy v6",
			input: []byte{0xC0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x20, 0x01, 0x04, 0x20, 0xFF, 0xFF, 0x10, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expect: &NLRI73{
				Length:        24,
				Distinguisher: 6,
				Color:         6,
				Endpoint:      net.ParseIP("2001:420:ffff:1013::1").To16(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLSNLRI73(tt.input)
			if err != nil {
				t.Fatalf("failed with error: %+v", err)
			}
			if got == nil {
				t.Fatalf("failed as returned object is nil")
			}
			if !reflect.DeepEqual(got, tt.expect) {
				t.Fatalf("Resulted object %+v does not match expected object %+v", *got, *tt.expect)
			}
		})
	}
}
