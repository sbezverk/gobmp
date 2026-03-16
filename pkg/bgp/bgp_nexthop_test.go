package bgp

import "testing"

func TestUnmarshalAttrNextHop(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want string
	}{
		{
			name: "empty input",
			b:    []byte{},
			want: "",
		},
		{
			name: "IPv4 4 bytes",
			b:    []byte{10, 0, 0, 1},
			want: "10.0.0.1",
		},
		{
			name: "IPv6 16 bytes",
			b:    []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: "2001:db8::1",
		},
		{
			name: "odd length 3 bytes",
			b:    []byte{10, 0, 0},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unmarshalAttrNextHop(tt.b)
			if got != tt.want {
				t.Errorf("unmarshalAttrNextHop(%v) = %q, want %q", tt.b, got, tt.want)
			}
		})
	}
}
