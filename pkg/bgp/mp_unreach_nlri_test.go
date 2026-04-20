package bgp

import (
	"errors"
	"strings"
	"testing"
)

// TestUnmarshalMPUnReachNLRI covers UnmarshalMPUnReachNLRI parse paths.
func TestUnmarshalMPUnReachNLRI(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		addPath    map[int]bool
		wantAFI    uint16
		wantSAFI   uint8
		wantRoutes int // expected len of WithdrawnRoutes
		wantErr    bool
	}{
		{
			name:    "empty input returns error",
			input:   []byte{},
			addPath: map[int]bool{},
			wantErr: true,
		},
		{
			name:    "1 byte input returns error",
			input:   []byte{0x00},
			addPath: map[int]bool{},
			wantErr: true,
		},
		{
			name:    "2 bytes input returns error",
			input:   []byte{0x00, 0x01},
			addPath: map[int]bool{},
			wantErr: true,
		},
		{
			name:       "IPv4 unicast withdrawal no prefixes",
			input:      []byte{0x00, 0x01, 0x01},
			addPath:    map[int]bool{},
			wantAFI:    1,
			wantSAFI:   1,
			wantRoutes: 0,
		},
		{
			name: "IPv4 unicast withdrawal with prefix bytes",
			// AFI=1, SAFI=1, then 4 bytes of withdrawn route data
			input:      []byte{0x00, 0x01, 0x01, 0x18, 0xC0, 0xA8, 0x01},
			addPath:    map[int]bool{},
			wantAFI:    1,
			wantSAFI:   1,
			wantRoutes: 4,
		},
		{
			name:       "IPv6 unicast AFI=2 SAFI=1",
			input:      []byte{0x00, 0x02, 0x01},
			addPath:    map[int]bool{},
			wantAFI:    2,
			wantSAFI:   1,
			wantRoutes: 0,
		},
		{
			name:       "L3VPN AFI=1 SAFI=128",
			input:      []byte{0x00, 0x01, 0x80},
			addPath:    map[int]bool{},
			wantAFI:    1,
			wantSAFI:   128,
			wantRoutes: 0,
		},
		{
			name:       "EVPN AFI=25 SAFI=70",
			input:      []byte{0x00, 0x19, 0x46},
			addPath:    map[int]bool{},
			wantAFI:    25,
			wantSAFI:   70,
			wantRoutes: 0,
		},
		{
			name:       "BGP-LS AFI=16388 SAFI=71",
			input:      []byte{0x40, 0x04, 0x47},
			addPath:    map[int]bool{},
			wantAFI:    16388,
			wantSAFI:   71,
			wantRoutes: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri, err := UnmarshalMPUnReachNLRI(tt.input, tt.addPath)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			mp := nlri.(*MPUnReachNLRI)
			if mp.AddressFamilyID != tt.wantAFI {
				t.Errorf("AFI: got %d, want %d", mp.AddressFamilyID, tt.wantAFI)
			}
			if mp.SubAddressFamilyID != tt.wantSAFI {
				t.Errorf("SAFI: got %d, want %d", mp.SubAddressFamilyID, tt.wantSAFI)
			}
			if len(mp.WithdrawnRoutes) != tt.wantRoutes {
				t.Errorf("WithdrawnRoutes len: got %d, want %d", len(mp.WithdrawnRoutes), tt.wantRoutes)
			}
		})
	}
}

// TestUnmarshalMPUnReachNLRI_SRv6Flag verifies the SRv6 flag is propagated.
func TestUnmarshalMPUnReachNLRI_SRv6Flag(t *testing.T) {
	// AFI=1, SAFI=128 (L3VPN)
	input := []byte{0x00, 0x01, 0x80}
	nlri, err := UnmarshalMPUnReachNLRI(input, map[int]bool{}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mp := nlri.(*MPUnReachNLRI)
	if !mp.SRv6 {
		t.Error("expected SRv6 flag to be true")
	}

	nlri2, err := UnmarshalMPUnReachNLRI(input, map[int]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mp2 := nlri2.(*MPUnReachNLRI)
	if mp2.SRv6 {
		t.Error("expected SRv6 flag to be false when not passed")
	}
}

// TestMPUnReachNLRI_GetAFISAFIType covers GetAFISAFIType for key AFI/SAFI combos.
func TestMPUnReachNLRI_GetAFISAFIType(t *testing.T) {
	tests := []struct {
		name     string
		afi      uint16
		safi     uint8
		wantType int
	}{
		{"IPv4 unicast", 1, 1, 1},
		{"IPv6 unicast", 2, 1, 2},
		{"IPv4 LU", 1, 4, 16},
		{"IPv6 LU", 2, 4, 17},
		{"IPv4 L3VPN", 1, 128, 18},
		{"IPv6 L3VPN", 2, 128, 19},
		{"EVPN", 25, 70, 24},
		{"VPLS", 25, 65, 23},
		{"BGP-LS", 16388, 71, 71},
		{"SR Policy v4", 1, 73, 25},
		{"SR Policy v6", 2, 73, 26},
		{"unknown", 99, 99, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MPUnReachNLRI{
				AddressFamilyID:    tt.afi,
				SubAddressFamilyID: tt.safi,
			}
			got := mp.GetAFISAFIType()
			if got != tt.wantType {
				t.Errorf("GetAFISAFIType() = %d, want %d", got, tt.wantType)
			}
		})
	}
}

// TestMPUnReachNLRI_IsIPv6NLRI covers the IsIPv6NLRI predicate.
func TestMPUnReachNLRI_IsIPv6NLRI(t *testing.T) {
	tests := []struct {
		name string
		afi  uint16
		want bool
	}{
		{"AFI=1 (IPv4) is false", 1, false},
		{"AFI=2 (IPv6) is true", 2, true},
		{"AFI=25 (L2VPN) is false", 25, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MPUnReachNLRI{AddressFamilyID: tt.afi}
			if got := mp.IsIPv6NLRI(); got != tt.want {
				t.Errorf("IsIPv6NLRI() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMPUnReachNLRI_GetNextHop verifies the no-op next-hop return.
func TestMPUnReachNLRI_GetNextHop(t *testing.T) {
	mp := &MPUnReachNLRI{}
	if got := mp.GetNextHop(); got != "" {
		t.Errorf("GetNextHop() = %q, want empty string", got)
	}
}

// TestMPUnReachNLRI_IsNextHopIPv6 verifies the no-op IPv6 NH return.
func TestMPUnReachNLRI_IsNextHopIPv6(t *testing.T) {
	mp := &MPUnReachNLRI{}
	if got := mp.IsNextHopIPv6(); got != false {
		t.Errorf("IsNextHopIPv6() = %v, want false", got)
	}
}

// TestMPUnReachNLRI_NLRINotFound verifies each getter returns NLRINotFoundError
// when the AFI/SAFI does not match.
func TestMPUnReachNLRI_NLRINotFound(t *testing.T) {
	// A minimal IPv4 unicast MP_UNREACH so the unmarshal works;
	// none of the specialised getters match SAFI=1.
	mp := &MPUnReachNLRI{
		AddressFamilyID:    1,
		SubAddressFamilyID: 1,
		WithdrawnRoutes:    []byte{},
		addPath:            map[int]bool{},
	}

	notFound := &NLRINotFoundError{}

	t.Run("GetNLRI71 wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRI71()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %v", err)
		}
	})
	t.Run("GetNLRI73 wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRI73()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %v", err)
		}
	})
	t.Run("GetNLRIL3VPN wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIL3VPN()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %v", err)
		}
	})
	t.Run("GetNLRIEVPN wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIEVPN()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %v", err)
		}
	})
	t.Run("GetNLRIVPLS wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIVPLS()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %v", err)
		}
	})
	t.Run("GetNLRIMulticast wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIMulticast()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %v", err)
		}
	})
	t.Run("GetNLRILU wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRILU()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %v", err)
		}
	})
	t.Run("GetNLRIMCASTVPN wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIMCASTVPN()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %v", err)
		}
	})
	t.Run("GetNLRIMVPN wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIMVPN()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %v", err)
		}
	})
	t.Run("GetNLRIRTC wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIRTC()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %v", err)
		}
	})

	// N11: Verify wrong AFI with correct SAFI is rejected
	t.Run("GetNLRI71 wrong AFI correct SAFI", func(t *testing.T) {
		mp71 := &MPUnReachNLRI{
			AddressFamilyID:    1, // should be 16388
			SubAddressFamilyID: 71,
			WithdrawnRoutes:    []byte{},
			addPath:            map[int]bool{},
		}
		_, err := mp71.GetNLRI71()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError for wrong AFI, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRI73 wrong AFI correct SAFI", func(t *testing.T) {
		mp73 := &MPUnReachNLRI{
			AddressFamilyID:    16388, // should be 1 or 2
			SubAddressFamilyID: 73,
			WithdrawnRoutes:    []byte{},
			addPath:            map[int]bool{},
		}
		_, err := mp73.GetNLRI73()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError for wrong AFI, got %T: %v", err, err)
		}
	})
}

// TestMPUnReachNLRI_GetFlowspecNLRI covers the flowspec branching logic.
func TestMPUnReachNLRI_GetFlowspecNLRI(t *testing.T) {
	tests := []struct {
		name         string
		afi          uint16
		safi         uint8
		wantErrMsg   string // substring expected in error string; "" means no error or NLRINotFoundError
		wantNotFound bool
	}{
		{
			name:         "AFI=1 SAFI=133 empty withdrawn (withdraw-all)",
			afi:          1,
			safi:         133,
			wantNotFound: false,
			wantErrMsg:   "",
		},
		{
			name:       "AFI=2 SAFI=133 IPv6 flowspec empty withdraw-all",
			afi:        2,
			safi:       133,
			wantErrMsg: "", // empty WithdrawnRoutes returns nil NLRI, nil error (withdraw-all)
		},
		{
			name:       "SAFI=134 AFI=1 VPN empty withdraw-all",
			afi:        1,
			safi:       134,
			wantErrMsg: "", // empty WithdrawnRoutes returns nil NLRI, nil error (withdraw-all)
		},
		{
			name:       "SAFI=134 AFI=2 VPN empty withdraw-all",
			afi:        2,
			safi:       134,
			wantErrMsg: "", // empty WithdrawnRoutes returns nil NLRI, nil error (withdraw-all)
		},
		{
			name:         "other SAFI returns NLRINotFoundError",
			afi:          1,
			safi:         1,
			wantNotFound: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MPUnReachNLRI{
				AddressFamilyID:    tt.afi,
				SubAddressFamilyID: tt.safi,
				WithdrawnRoutes:    []byte{},
				addPath:            map[int]bool{},
			}
			_, err := mp.GetFlowspecNLRI()
			if tt.wantErrMsg == "" && !tt.wantNotFound {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantNotFound {
				notFound := &NLRINotFoundError{}
				if !errors.As(err, &notFound) {
					t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
				}
				return
			}
			if tt.wantErrMsg != "" {
				if got := err.Error(); !strings.Contains(got, tt.wantErrMsg) {
					t.Errorf("error %q does not contain %q", got, tt.wantErrMsg)
				}
			}
		})
	}
}

// TestMPUnReachNLRI_GetFlowspecNLRI_IPv6WithData verifies the IPv6 flowspec parse path
// with actual wire-format data (non-empty WithdrawnRoutes, AFI=2, SAFI=133).
func TestMPUnReachNLRI_GetFlowspecNLRI_IPv6WithData(t *testing.T) {
	// 2001:db8::/32 destination prefix, offset=0
	mp := &MPUnReachNLRI{
		AddressFamilyID:    2,
		SubAddressFamilyID: 133,
		WithdrawnRoutes:    []byte{0x07, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8},
		addPath:            map[int]bool{},
	}
	nlri, err := mp.GetFlowspecNLRI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri == nil {
		t.Fatal("expected non-nil NLRI for IPv6 flowspec withdrawal")
	}
}

// TestMPUnReachNLRI_GetFlowspecNLRI_VPNWithData verifies SAFI=134 VPN FlowSpec parse path
// with actual wire-format data.
func TestMPUnReachNLRI_GetFlowspecNLRI_VPNWithData(t *testing.T) {
	mp := &MPUnReachNLRI{
		AddressFamilyID:    1,
		SubAddressFamilyID: 134,
		WithdrawnRoutes: []byte{
			0x0b,                                           // Length: 11
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, // RD 100:1
			0x01, 0x08, 0x0a, // Type1 Dest 10.0.0.0/8
		},
		addPath: map[int]bool{},
	}
	nlri, err := mp.GetFlowspecNLRI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri == nil {
		t.Fatal("expected non-nil NLRI for VPN flowspec withdrawal")
	}
	if nlri.RD != "100:1" {
		t.Errorf("RD = %q, want %q", nlri.RD, "100:1")
	}
}

// TestMPUnReachNLRI_GetAllFlowspecNLRI covers all branching paths of GetAllFlowspecNLRI.
func TestMPUnReachNLRI_GetAllFlowspecNLRI(t *testing.T) {
	tests := []struct {
		name         string
		afi          uint16
		safi         uint8
		routes       []byte
		wantCount    int
		wantNilSlice bool
		wantErrMsg   string
		wantNotFound bool
	}{
		{
			// IPv4 single NLRI: 10.0.0.0/8
			name:      "AFI=1 SAFI=133 single IPv4 NLRI",
			afi:       1,
			safi:      133,
			routes:    []byte{0x03, 0x01, 0x08, 0x0a},
			wantCount: 1,
		},
		{
			// IPv6 single NLRI: 2001:db8::/32 offset=0
			name:      "AFI=2 SAFI=133 single IPv6 NLRI",
			afi:       2,
			safi:      133,
			routes:    []byte{0x07, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8},
			wantCount: 1,
		},
		{
			// RFC 8955 §4: empty MP_UNREACH_NLRI is a withdraw-all signal.
			name:         "AFI=1 SAFI=133 withdraw-all (empty routes)",
			afi:          1,
			safi:         133,
			routes:       []byte{},
			wantNilSlice: true,
		},
		{
			// RFC 8956 §3: empty MP_UNREACH_NLRI is a withdraw-all signal.
			name:         "AFI=2 SAFI=133 withdraw-all (empty routes)",
			afi:          2,
			safi:         133,
			routes:       []byte{},
			wantNilSlice: true,
		},
		{
			name:         "SAFI=134 VPN empty withdraw-all",
			afi:          1,
			safi:         134,
			routes:       []byte{},
			wantNilSlice: true,
		},
		{
			name: "SAFI=134 VPN with real data",
			afi:  1,
			safi: 134,
			routes: []byte{
				0x0b,                                           // Length: 11
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, // RD 100:1
				0x01, 0x08, 0x0a, // Type1 Dest 10.0.0.0/8
			},
			wantCount: 1,
		},
		{
			name:         "non-flowspec SAFI returns NLRINotFoundError",
			afi:          1,
			safi:         1,
			wantNotFound: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MPUnReachNLRI{
				AddressFamilyID:    tt.afi,
				SubAddressFamilyID: tt.safi,
				WithdrawnRoutes:    tt.routes,
				addPath:            map[int]bool{},
			}
			nlris, err := mp.GetAllFlowspecNLRI()
			if tt.wantNotFound {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				notFound := &NLRINotFoundError{}
				if !errors.As(err, &notFound) {
					t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
				}
				return
			}
			if tt.wantErrMsg != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNilSlice {
				if nlris != nil {
					t.Errorf("expected nil slice for withdraw-all, got %v", nlris)
				}
				return
			}
			if len(nlris) != tt.wantCount {
				t.Errorf("got %d NLRIs, want %d", len(nlris), tt.wantCount)
			}
		})
	}
}

// TestMPUnReachNLRI_GetNLRIUnicast_match verifies the SAFI match branch is entered.
func TestMPUnReachNLRI_GetNLRIUnicast_match(t *testing.T) {
	// A valid single IPv4 /24 prefix: 0x18 0x0A 0x0A 0x0A (10.10.10.0/24)
	mp := &MPUnReachNLRI{
		AddressFamilyID:    1,
		SubAddressFamilyID: 1,
		WithdrawnRoutes:    []byte{0x18, 0x0A, 0x0A, 0x0A},
		addPath:            map[int]bool{},
	}
	nlri, err := mp.GetNLRIUnicast()
	if err != nil {
		t.Fatalf("GetNLRIUnicast() unexpected error: %v", err)
	}
	if nlri == nil {
		t.Fatal("GetNLRIUnicast() returned nil NLRI")
	}
}

// nodeNLRI71Bytes is a minimal valid BGP-LS Node NLRI (type=1) for GetNLRI71 tests.
var nodeNLRI71Bytes = []byte{
	0x00, 0x01, 0x00, 0x27, // type=1 (Node), length=39
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // proto=2, ident=0
	0x01, 0x00, 0x00, 0x1a, // LocalNode desc type=256, len=26
	0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, // AS=65000
	0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // BGP-LS ID=0
	0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Router-ID
}

func TestMPUnReachNLRI_GetNLRI71_NoAddPath(t *testing.T) {
	mp := &MPUnReachNLRI{
		AddressFamilyID:    16388,
		SubAddressFamilyID: 71,
		WithdrawnRoutes:    nodeNLRI71Bytes,
		addPath:            map[int]bool{71: false},
	}
	nlri, err := mp.GetNLRI71()
	if err != nil {
		t.Fatalf("GetNLRI71() unexpected error: %v", err)
	}
	if nlri == nil || len(nlri.NLRI) == 0 {
		t.Fatal("GetNLRI71() returned nil or empty NLRI")
	}
	if nlri.PathID != 0 {
		t.Errorf("expected PathID=0, got %d", nlri.PathID)
	}
}

func TestMPUnReachNLRI_GetNLRI71_WithAddPath(t *testing.T) {
	// Prepend 4-byte Path-ID=3 before the Node NLRI payload
	payload := append([]byte{0x00, 0x00, 0x00, 0x03}, nodeNLRI71Bytes...)
	mp := &MPUnReachNLRI{
		AddressFamilyID:    16388,
		SubAddressFamilyID: 71,
		WithdrawnRoutes:    payload,
		addPath:            map[int]bool{71: true},
	}
	nlri, err := mp.GetNLRI71()
	if err != nil {
		t.Fatalf("GetNLRI71() with Add Path unexpected error: %v", err)
	}
	if nlri.PathID != 3 {
		t.Errorf("expected PathID=3, got %d", nlri.PathID)
	}
	if len(nlri.NLRI) == 0 {
		t.Fatal("GetNLRI71() with Add Path returned empty NLRI")
	}
}
