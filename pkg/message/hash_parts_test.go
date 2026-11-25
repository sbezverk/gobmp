package message

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
)

// TestHashParts checks hashParts returns the digest of the parts streamed to
// an MD5 hash, each followed by a zero octet, also for parts that overflow its
// stack buffer.
func TestHashParts(t *testing.T) {
	for _, parts := range [][]string{
		nil,
		{"", ""},
		{"a\x00b", ""},
		{"unicast", "66efff4c945d3c3b87fc271b47d456db", "10.0.0.0", "24", "true", "0", ""},
		{strings.Repeat("x", 255)},
		{strings.Repeat("x", 4096), "y"},
	} {
		h := md5.New()
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
		if got, want := hashParts(parts...), hex.EncodeToString(h.Sum(nil)); got != want {
			t.Errorf("hashParts(%.20q) = %s, want %s", parts, got, want)
		}
	}
}
