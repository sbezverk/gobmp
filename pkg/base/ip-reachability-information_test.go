package base

import (
	"bytes"
	"testing"
)

func TestUnmarshalIPReachabilityInformation(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantBits    uint8
		wantPrefix  []byte
		wantErr     bool
	}{
		{
			name:       "ipv4 /24 prefix",
			input:      []byte{24, 192, 168, 1},
			wantBits:   24,
			wantPrefix: []byte{192, 168, 1},
		},
		{
			name:       "ipv4 /32 prefix",
			input:      []byte{32, 10, 0, 0, 1},
			wantBits:   32,
			wantPrefix: []byte{10, 0, 0, 1},
		},
		{
			name:       "ipv4 /25 non-byte-aligned prefix",
			input:      []byte{25, 192, 168, 1, 128},
			wantBits:   25,
			wantPrefix: []byte{192, 168, 1, 128},
		},
		{
			name:       "ipv4 /0 default route",
			input:      []byte{0},
			wantBits:   0,
			wantPrefix: []byte{},
		},
		{
			name:       "ipv6 /128 prefix",
			input:      append([]byte{128}, make([]byte, 16)...),
			wantBits:   128,
			wantPrefix: make([]byte, 16),
		},
		{
			name:       "ipv6 /48 prefix",
			input:      []byte{48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01},
			wantBits:   48,
			wantPrefix: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalIPReachabilityInformation(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalIPReachabilityInformation() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.LengthInBits != tt.wantBits {
				t.Errorf("LengthInBits = %d, want %d", got.LengthInBits, tt.wantBits)
			}
			if !bytes.Equal(got.Prefix, tt.wantPrefix) {
				t.Errorf("Prefix = %v, want %v", got.Prefix, tt.wantPrefix)
			}
		})
	}
}
