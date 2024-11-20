package bgp

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalMPReachNLRI(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		expect  *MPReachNLRI
		srv6    bool
		addPath map[int]bool
	}{
		{
			name:  "issue_173",
			input: []byte{0x00, 0x02, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x0A, 0x98, 0xB7, 0x0B, 0x00, 0x10, 0x20, 0x01},
			expect: &MPReachNLRI{
				AddressFamilyID:      2,
				SubAddressFamilyID:   1,
				NextHopAddressLength: 16,
				NextHopAddress:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x0A, 0x98, 0xB7, 0x0B},
				NLRI:                 []byte{0x10, 0x20, 0x01},
				addPath:              map[int]bool{},
			},
			srv6:    false,
			addPath: map[int]bool{},
		},
		{
			name:  "invalid next hop for Peer type 3",
			input: []byte{0x00, 0x01, 0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x13, 0x88, 0x11, 0x00, 0x01, 0x01, 0x01, 0x0A, 0x01, 0x00, 0x01, 0x0B, 0x0B, 0x0B, 0x0B, 0x70, 0x13, 0x88, 0x11, 0x00, 0x01, 0x01, 0x01, 0x0A, 0x01, 0x00, 0x01, 0x01, 0x64, 0x01},
			expect: &MPReachNLRI{
				AddressFamilyID:      1,
				SubAddressFamilyID:   128,
				NextHopAddressLength: 8,
				NextHopAddress:       []byte{0, 0, 0, 0, 0, 0, 0, 0},
				NLRI:                 []byte{0x78, 0x13, 0x88, 0x11, 0x00, 0x01, 0x01, 0x01, 0x0A, 0x01, 0x00, 0x01, 0x0B, 0x0B, 0x0B, 0x0B, 0x70, 0x13, 0x88, 0x11, 0x00, 0x01, 0x01, 0x01, 0x0A, 0x01, 0x00, 0x01, 0x01, 0x64, 0x01},
				addPath:              map[int]bool{},
			},
			srv6:    false,
			addPath: map[int]bool{},
		},
		{
			name:  "possible panic in ls nlri 71",
			input: []byte{64, 4, 71, 16, 36, 9, 128, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 4, 0, 66, 2, 0, 0, 0, 0, 0, 0, 95, 80, 1, 0, 0, 26, 2, 0, 0, 4, 0, 0, 95, 80, 2, 1, 0, 4, 211, 136, 191, 255, 2, 3, 0, 6, 33, 17, 54, 25, 18, 54, 1, 9, 0, 17, 127, 36, 9, 128, 30, 0, 240, 0, 1, 0, 0, 0, 0, 0, 0, 0, 202},
			expect: &MPReachNLRI{
				AddressFamilyID:      16388,
				SubAddressFamilyID:   71,
				NextHopAddressLength: 16,
				NextHopAddress:       []byte{36, 9, 128, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11},
				NLRI:                 []byte{0, 4, 0, 66, 2, 0, 0, 0, 0, 0, 0, 95, 80, 1, 0, 0, 26, 2, 0, 0, 4, 0, 0, 95, 80, 2, 1, 0, 4, 211, 136, 191, 255, 2, 3, 0, 6, 33, 17, 54, 25, 18, 54, 1, 9, 0, 17, 127, 36, 9, 128, 30, 0, 240, 0, 1, 0, 0, 0, 0, 0, 0, 0, 202},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := UnmarshalMPReachNLRI(tt.input, tt.srv6, tt.addPath)
			if err != nil {
				t.Fatalf("failed to unmarshal MP Reach NLRI with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, actual) {
				t.Logf("differences: %+v", deep.Equal(tt.expect, actual))
				t.Fatal("the expected object does not match the actual")
			}
		})
	}
}
