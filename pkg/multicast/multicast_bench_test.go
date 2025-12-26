package multicast

import (
	"testing"
)

func BenchmarkUnmarshalMulticastNLRI(b *testing.B) {
	tests := []struct {
		name   string
		input  []byte
		pathID bool
	}{
		{
			name:   "single prefix no pathID",
			input:  []byte{0x18, 0xe0, 0x00, 0x01},
			pathID: false,
		},
		{
			name:   "single prefix with pathID",
			input:  []byte{0x00, 0x00, 0x00, 0x01, 0x20, 0xe0, 0x00, 0x00, 0x01},
			pathID: true,
		},
		{
			name:   "multiple prefixes with pathID",
			input:  []byte{0x00, 0x00, 0x00, 0x01, 0x18, 0xe0, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x18, 0xe0, 0x02, 0x02, 0x00, 0x00, 0x00, 0x01, 0x18, 0xe0, 0x03, 0x03},
			pathID: true,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = UnmarshalMulticastNLRI(tt.input, tt.pathID)
			}
		})
	}
}
