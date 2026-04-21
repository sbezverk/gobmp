package bgp

import "testing"

func TestMPUnReachNLRIGetNLRIRTC(t *testing.T) {
	// Valid: AFI 1, SAFI 132, wildcard RTC NLRI (length=0 per RFC 4684 §4)
	unreach := &MPUnReachNLRI{AddressFamilyID: 1, SubAddressFamilyID: 132, WithdrawnRoutes: []byte{0x00}}
	if _, err := unreach.GetNLRIRTC(); err != nil {
		t.Errorf("AFI=1 SAFI=132: unexpected error: %v", err)
	}

	// Valid: AFI 2, SAFI 132
	unreach2 := &MPUnReachNLRI{AddressFamilyID: 2, SubAddressFamilyID: 132, WithdrawnRoutes: []byte{0x00}}
	if _, err := unreach2.GetNLRIRTC(); err != nil {
		t.Errorf("AFI=2 SAFI=132: unexpected error: %v", err)
	}

	// Invalid: wrong AFI (25 = L2VPN), SAFI 132 — must be rejected
	unreach3 := &MPUnReachNLRI{AddressFamilyID: 25, SubAddressFamilyID: 132, WithdrawnRoutes: []byte{0x00}}
	if _, err := unreach3.GetNLRIRTC(); err == nil {
		t.Error("AFI=25 SAFI=132: expected error, got nil")
	}
}
