package bgpls

import (
	"reflect"
	"testing"
)

func TestGetNodeSRMSPreference(t *testing.T) {
	// RFC 9085 §2.1.5: TLV 1037 (0x040d) contains exactly one octet.
	zero, maximum := uint8(0), uint8(255)
	tests := []struct {
		name string
		wire []byte
		want *uint8
	}{
		{
			name: "no valid preference",
			wire: []byte{
				0x04, 0x02, 0x00, 0x01, 'r', // Unrelated TLV with a one-octet value.
				0x04, 0x0d, 0x00, 0x00,
				0x04, 0x0d, 0x00, 0x02, 0x00, 0xff,
			},
		},
		{
			name: "first valid value can be zero",
			wire: []byte{
				0x04, 0x02, 0x00, 0x01, 'r',
				0x04, 0x0d, 0x00, 0x02, 0x01, 0x02,
				0x04, 0x0d, 0x00, 0x01, 0x00,
				0x04, 0x0d, 0x00, 0x01, 0xff,
			},
			want: &zero,
		},
		{
			name: "maximum preference",
			wire: []byte{0x04, 0x0d, 0x00, 0x01, 0xff},
			want: &maximum,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri, err := UnmarshalBGPLSNLRI(tt.wire)
			if err != nil {
				t.Fatalf("UnmarshalBGPLSNLRI() error: %v", err)
			}
			got := nlri.GetNodeSRMSPreference()
			if !reflect.DeepEqual(got, tt.want) {
				if got != nil && tt.want != nil {
					t.Errorf("GetNodeSRMSPreference() = %d, want %d", *got, *tt.want)
				} else {
					t.Errorf("GetNodeSRMSPreference() present = %t, want %t", got != nil, tt.want != nil)
				}
			}
		})
	}
}
