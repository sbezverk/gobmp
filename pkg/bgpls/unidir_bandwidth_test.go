package bgpls

import "testing"

func TestUnidirectionalBandwidthKbps(t *testing.T) {
	// RFC 8571 §§2.5–2.7: type and length precede a binary32 value in bytes/s.
	tests := []struct {
		name    string
		wire    []byte
		want    [3]uint64
		present [3]bool
	}{
		{
			name: "TLV type selects the metric",
			wire: []byte{
				0x04, 0x60, 0, 4, 0x4d, 0x6e, 0x6b, 0x28,
				0x04, 0x5e, 0, 4, 0x4e, 0x32, 0xd0, 0x5e,
				0x04, 0x5f, 0, 4, 0x4e, 0x26, 0xe4, 0x9c,
			},
			want:    [3]uint64{6000000, 5600000, 2000000},
			present: [3]bool{true, true, true},
		},
		{
			name: "zero, truncation, and largest representable input below the limit",
			wire: []byte{
				0x04, 0x5e, 0, 4, 0, 0, 0, 0,
				0x04, 0x5f, 0, 4, 0x43, 0x3b, 0x80, 0, // 187.5 bytes/s
				0x04, 0x60, 0, 4, 0x62, 0xf9, 0xff, 0xff,
			},
			want:    [3]uint64{0, 1, 18446742947809644773},
			present: [3]bool{true, true, true},
		},
		{
			name: "short, absent, and overlong values",
			wire: []byte{
				0x04, 0x5e, 0, 3, 0x43, 0x3b, 0x80,
				0x04, 0x60, 0, 5, 0x43, 0x3b, 0x80, 0, 0,
			},
		},
		{
			name: "NaN, negative, and overflowing values",
			wire: []byte{
				0x04, 0x5e, 0, 4, 0x7f, 0xc0, 0, 0,
				0x04, 0x5f, 0, 4, 0xbf, 0x80, 0, 0,
				0x04, 0x60, 0, 4, 0x62, 0xfa, 0, 0, // Exactly 2^64 kbps.
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := UnmarshalBGPLSNLRI(tt.wire)
			if err != nil {
				t.Fatalf("decode BGP-LS attributes: %v", err)
			}
			got := [...]*uint64{
				attrs.GetUnidirResidualBandwidthKbps(),
				attrs.GetUnidirAvailableBandwidthKbps(),
				attrs.GetUnidirUtilizedBandwidthKbps(),
			}
			for i, value := range got {
				if !tt.present[i] {
					if value != nil {
						t.Errorf("TLV %d = %d kbps, want absent", 1118+i, *value)
					}
					continue
				}
				if value == nil {
					t.Errorf("TLV %d absent, want %d kbps", 1118+i, tt.want[i])
				} else if *value != tt.want[i] {
					t.Errorf("TLV %d = %d kbps, want %d", 1118+i, *value, tt.want[i])
				}
			}
		})
	}
}
