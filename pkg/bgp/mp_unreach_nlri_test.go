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
			name:       "AFI=2 SAFI=133 not implemented",
			afi:        2,
			safi:       133,
			wantErrMsg: "not yet implemented",
		},
		{
			name:       "SAFI=134 AFI=1 VPN not implemented",
			afi:        1,
			safi:       134,
			wantErrMsg: "not yet implemented",
		},
		{
			name:       "SAFI=134 AFI=2 VPN not implemented",
			afi:        2,
			safi:       134,
			wantErrMsg: "not yet implemented",
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
