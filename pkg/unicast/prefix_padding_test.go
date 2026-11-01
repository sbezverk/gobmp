package unicast

import (
	"bytes"
	"testing"
)

func TestLUPrefixPaddingOwnership(t *testing.T) {
	for _, tt := range []struct {
		name       string
		wire, want []byte
	}{
		{"default", []byte{24, 0, 1, 1}, []byte{}},
		{"label", []byte{41, 0, 1, 1, 10, 1, 127}, []byte{10, 1, 0}},
		{"two labels", []byte{65, 0, 1, 0, 0, 2, 1, 10, 1, 127}, []byte{10, 1, 0}},
		{"withdrawal marker", []byte{41, 128, 0, 0, 10, 1, 127}, []byte{10, 1, 0}},
		{"boundary", []byte{32, 0, 1, 1, 10}, []byte{10}},
		{"truncated", []byte{41, 0, 1, 1, 10}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			original := bytes.Clone(tt.wire)
			routes, err := UnmarshalLUNLRI(tt.wire, false)
			if tt.want == nil {
				if err == nil {
					t.Fatal("expected truncation error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(routes.NLRI) != 1 || !bytes.Equal(routes.NLRI[0].Prefix, tt.want) {
				t.Fatalf("routes = %+v, want prefix %x", routes, tt.want)
			}
			if len(routes.NLRI[0].Prefix) > 0 {
				routes.NLRI[0].Prefix[0] ^= 255
			}
			if !bytes.Equal(tt.wire, original) {
				t.Fatal("prefix aliases input")
			}
		})
	}
}
