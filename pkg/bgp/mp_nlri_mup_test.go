package bgp

import "testing"

// mupISDNLRI is an Interwork Segment Discovery route for RD 100:100 and
// prefix 10.10.10.0/24.
var mupISDNLRI = []byte{
	0x01, 0x00, 0x01, 0x0c,
	0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
	0x18, 0x0a, 0x0a, 0x0a,
}

func TestMPReachNLRIGetNLRIMUP(t *testing.T) {
	mp := &MPReachNLRI{
		AddressFamilyID:    1,
		SubAddressFamilyID: 85,
		NLRI:               mupISDNLRI,
	}
	route, err := mp.GetNLRIMUP()
	if err != nil {
		t.Fatalf("GetNLRIMUP() unexpected error: %+v", err)
	}
	if len(route.Route) != 1 {
		t.Fatalf("GetNLRIMUP() returned %d NLRIs, want 1", len(route.Route))
	}
	if got := route.Route[0].GetMUPRD().String(); got != "100:100" {
		t.Fatalf("GetMUPRD() = %s, want 100:100", got)
	}

	mp.SubAddressFamilyID = 1
	if _, err := mp.GetNLRIMUP(); err == nil {
		t.Fatal("GetNLRIMUP() expected an error for a non MUP SAFI, got none")
	}
}

func TestMPUnReachNLRIGetNLRIMUP(t *testing.T) {
	mp := &MPUnReachNLRI{
		AddressFamilyID:    2,
		SubAddressFamilyID: 85,
		WithdrawnRoutes: []byte{
			0x01, 0x00, 0x02, 0x18,
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
			0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}
	route, err := mp.GetNLRIMUP()
	if err != nil {
		t.Fatalf("GetNLRIMUP() unexpected error: %+v", err)
	}
	if len(route.Route) != 1 {
		t.Fatalf("GetNLRIMUP() returned %d NLRIs, want 1", len(route.Route))
	}
	if got := route.Route[0].GetMUPRouteType(); got != 2 {
		t.Fatalf("GetMUPRouteType() = %d, want 2", got)
	}

	mp.SubAddressFamilyID = 128
	if _, err := mp.GetNLRIMUP(); err == nil {
		t.Fatal("GetNLRIMUP() expected an error for a non MUP SAFI, got none")
	}
}

// The Add Path capability map is keyed by NLRI message type, so a session
// that negotiated Add Path for the BGP-MUP SAFI reaches the MUP parser.
func TestMPReachNLRIGetNLRIMUPAddPath(t *testing.T) {
	mp := &MPReachNLRI{
		AddressFamilyID:    1,
		SubAddressFamilyID: 85,
		NLRI:               append([]byte{0x00, 0x00, 0x00, 0x07}, mupISDNLRI...),
		addPath: map[int]bool{
			NLRIMessageType(1, 85): true,
		},
	}
	route, err := mp.GetNLRIMUP()
	if err != nil {
		t.Fatalf("GetNLRIMUP() unexpected error: %+v", err)
	}
	if len(route.Route) != 1 {
		t.Fatalf("GetNLRIMUP() returned %d NLRIs, want 1", len(route.Route))
	}
	if route.Route[0].PathID != 7 {
		t.Fatalf("PathID = %d, want 7", route.Route[0].PathID)
	}
}
