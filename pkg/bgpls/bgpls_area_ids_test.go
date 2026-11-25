package bgpls

import (
	"slices"
	"testing"
)

func TestGetISISAreaIDsFromWire(t *testing.T) {
	// RFC 9552 §5.3.1.2 carries each address in a separate TLV 1027.
	// RFC 7898 §3.2.2 gives the IS-IS area address length as 1–13 octets.
	tests := []struct {
		name string
		wire []byte
		want []string
	}{
		{
			name: "minimum length",
			wire: []byte{0x04, 0x03, 0, 1, 0x49},
			want: []string{"49"},
		},
		{
			name: "maximum length",
			wire: []byte{0x04, 0x03, 0, 13, 0x49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab},
			want: []string{"490000000000000000000000ab"},
		},
		{
			name: "wire order and duplicates",
			wire: []byte{
				0x04, 0x03, 0, 3, 0x49, 0, 0xcd,
				0x04, 0x02, 0, 1, 'n', // Node Name, ignored
				0x04, 0x03, 0, 1, 0x47,
				0x04, 0x03, 0, 3, 0x49, 0, 0xcd,
			},
			want: []string{"4900cd", "47", "4900cd"},
		},
		{
			name: "invalid lengths beside a valid area",
			wire: []byte{
				0x04, 0x03, 0, 0,
				0x04, 0x03, 0, 14, 0x49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
				0x04, 0x03, 0, 2, 0x49, 0,
			},
			want: []string{"4900"},
		},
		{
			name: "no valid area TLV",
			wire: []byte{
				0x04, 0x02, 0, 1, 'n',
				0x04, 0x03, 0, 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, err := UnmarshalBGPLSNLRI(tt.wire)
			if err != nil {
				t.Fatalf("UnmarshalBGPLSNLRI: %v", err)
			}
			if got := attr.GetISISAreaIDs(); !slices.Equal(got, tt.want) {
				t.Errorf("GetISISAreaIDs() = %q, want %q", got, tt.want)
			}
		})
	}
}
