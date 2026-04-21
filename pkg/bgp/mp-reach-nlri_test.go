package bgp

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestMPReachNLRIGetNLRIRTC(t *testing.T) {
	// Valid: AFI 1, SAFI 132, wildcard RTC NLRI (length=0 per RFC 4684 §4)
	reach := &MPReachNLRI{AddressFamilyID: 1, SubAddressFamilyID: 132, NLRI: []byte{0x00}}
	if _, err := reach.GetNLRIRTC(); err != nil {
		t.Errorf("AFI=1 SAFI=132: unexpected error: %v", err)
	}

	// Valid: AFI 2, SAFI 132
	reach2 := &MPReachNLRI{AddressFamilyID: 2, SubAddressFamilyID: 132, NLRI: []byte{0x00}}
	if _, err := reach2.GetNLRIRTC(); err != nil {
		t.Errorf("AFI=2 SAFI=132: unexpected error: %v", err)
	}

	// Invalid: wrong AFI (25 = L2VPN), SAFI 132 — must be rejected
	reach3 := &MPReachNLRI{AddressFamilyID: 25, SubAddressFamilyID: 132, NLRI: []byte{0x00}}
	if _, err := reach3.GetNLRIRTC(); err == nil {
		t.Error("AFI=25 SAFI=132: expected error, got nil")
	}
}

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
