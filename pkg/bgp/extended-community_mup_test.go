package bgp

import "testing"

// The byte vectors below were produced by GoBGP's serializer for the BGP MUP
// Extended Community of draft-ietf-bess-mup-safi-01 Section 3.2.
func TestMUPExtendedCommunity(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "Direct Segment 2-octet AS",
			input: []byte{0x0c, 0x00, 0x00, 0x64, 0x00, 0x00, 0x27, 0x10},
			want:  "mup-ds=100:10000",
		},
		{
			name:  "Direct Segment IPv4 address",
			input: []byte{0x0c, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x64},
			want:  "mup-ds=10.0.0.1:100",
		},
		{
			name:  "Direct Segment 4-octet AS",
			input: []byte{0x0c, 0x02, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x64},
			want:  "mup-ds=65550:100",
		},
		{
			name:  "Interwork Segment 2-octet AS",
			input: []byte{0x0c, 0x03, 0x00, 0x64, 0x00, 0x00, 0x27, 0x10},
			want:  "mup-is=100:10000",
		},
		{
			name:  "Interwork Segment IPv4 address",
			input: []byte{0x0c, 0x04, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x64},
			want:  "mup-is=10.0.0.1:100",
		},
		{
			name:  "Interwork Segment 4-octet AS",
			input: []byte{0x0c, 0x05, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x64},
			want:  "mup-is=65550:100",
		},
		{
			name:  "unknown sub type",
			input: []byte{0x0c, 0x06, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x64},
			want:  "Subtype unknown=65550:100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exts, err := UnmarshalBGPExtCommunity(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalBGPExtCommunity() unexpected error: %+v", err)
			}
			if len(exts) != 1 {
				t.Fatalf("UnmarshalBGPExtCommunity() returned %d communities, want 1", len(exts))
			}
			if exts[0].SubType == nil {
				t.Fatal("UnmarshalBGPExtCommunity() did not parse the sub type")
			}
			if got := exts[0].String(); got != tt.want {
				t.Fatalf("String() = %s, want %s", got, tt.want)
			}
		})
	}
}
