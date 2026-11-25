package message

import "testing"

func TestHexColon(t *testing.T) {
	b := []byte{0x00, 0x0a, 0xff, 0x7f, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55}
	for n, want := range map[int]string{
		0:  "",
		1:  "00",
		3:  "00:0a:ff",
		10: "00:0a:ff:7f:80:11:22:33:44:55",
	} {
		if got := hexColon(b, n); got != want {
			t.Errorf("hexColon(%d) = %q, want %q", n, got, want)
		}
	}
}
