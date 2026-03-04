package bgp

import (
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// UnmarshalMPReachNLRI error paths
// ---------------------------------------------------------------------------

func TestUnmarshalMPReachNLRI_Errors(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{
			name:    "too short – less than 3 bytes",
			input:   []byte{0x00, 0x01},
			wantErr: "not enough bytes",
		},
		{
			name: "NextHop length exceeds buffer",
			// AFI=1, SAFI=1, NextHopLen=16 but only 4 NH bytes follow
			input:   []byte{0x00, 0x01, 0x01, 0x10, 0xC0, 0xA8, 0x01, 0x01},
			wantErr: "not enough bytes",
		},
		{
			name: "missing Reserved byte",
			// AFI=1, SAFI=1, NextHopLen=4, 4 NH bytes, then buffer ends (no Reserved)
			input:   []byte{0x00, 0x01, 0x01, 0x04, 0xC0, 0xA8, 0x01, 0x01},
			wantErr: "missing Reserved byte",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalMPReachNLRI(tt.input, false, map[int]bool{})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MPReachNLRI.GetAFISAFIType
// ---------------------------------------------------------------------------

func TestMPReachNLRI_GetAFISAFIType(t *testing.T) {
	tests := []struct {
		afi      uint16
		safi     uint8
		wantType int
	}{
		{1, 1, 1},
		{2, 1, 2},
		{1, 128, 18},
		{2, 128, 19},
		{25, 70, 24},
		{25, 65, 23},
		{16388, 71, 71},
	}
	for _, tt := range tests {
		mp := &MPReachNLRI{AddressFamilyID: tt.afi, SubAddressFamilyID: tt.safi}
		got := mp.GetAFISAFIType()
		if got != tt.wantType {
			t.Errorf("GetAFISAFIType() AFI=%d SAFI=%d = %d, want %d", tt.afi, tt.safi, got, tt.wantType)
		}
	}
}

// ---------------------------------------------------------------------------
// MPReachNLRI.IsIPv6NLRI
// ---------------------------------------------------------------------------

func TestMPReachNLRI_IsIPv6NLRI(t *testing.T) {
	tests := []struct {
		afi  uint16
		want bool
	}{
		{1, false},
		{2, true},
		{25, false},
	}
	for _, tt := range tests {
		mp := &MPReachNLRI{AddressFamilyID: tt.afi}
		if got := mp.IsIPv6NLRI(); got != tt.want {
			t.Errorf("IsIPv6NLRI() AFI=%d = %v, want %v", tt.afi, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// MPReachNLRI.IsNextHopIPv6
// ---------------------------------------------------------------------------

func TestMPReachNLRI_IsNextHopIPv6(t *testing.T) {
	tests := []struct {
		nhLen uint8
		want  bool
	}{
		{4, false},
		{8, false},
		{12, false},
		{16, true},
		{24, true},
		{32, true},
		{48, true},
		{0, false},
	}
	for _, tt := range tests {
		mp := &MPReachNLRI{NextHopAddressLength: tt.nhLen}
		if got := mp.IsNextHopIPv6(); got != tt.want {
			t.Errorf("IsNextHopIPv6() nhLen=%d = %v, want %v", tt.nhLen, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// MPReachNLRI.GetNextHop
// ---------------------------------------------------------------------------

func TestMPReachNLRI_GetNextHop(t *testing.T) {
	tests := []struct {
		name    string
		nhLen   uint8
		nhBytes []byte
		want    string
	}{
		{
			name:    "IPv4 (len=4)",
			nhLen:   4,
			nhBytes: []byte{192, 168, 1, 1},
			want:    "192.168.1.1",
		},
		{
			name:    "Peer3 RD+IPv4 (len=8)",
			nhLen:   8,
			nhBytes: []byte{0, 0, 0, 0, 10, 0, 0, 1},
			want:    "10.0.0.1",
		},
		{
			name:    "RD+IPv4 (len=12)",
			nhLen:   12,
			nhBytes: []byte{0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2},
			want:    "10.0.0.2",
		},
		{
			name:    "IPv6 (len=16)",
			nhLen:   16,
			nhBytes: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want:    "2001:db8::1",
		},
		{
			name:  "RD+IPv6 (len=24)",
			nhLen: 24,
			nhBytes: append(
				[]byte{0, 0, 0, 0, 0, 0, 0, 0},                                        // 8 bytes RD
				[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}..., // 16 bytes IPv6
			),
			want: "2001:db8::2",
		},
		{
			name:  "IPv6+LinkLocal (len=32)",
			nhLen: 32,
			nhBytes: append(
				[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}, // global
				[]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}...,    // link-local
			),
			want: "2001:db8::3,fe80::1",
		},
		{
			name:    "invalid length returns error string",
			nhLen:   99,
			nhBytes: make([]byte, 99),
			want:    "invalid next hop address length",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MPReachNLRI{
				NextHopAddressLength: tt.nhLen,
				NextHopAddress:       tt.nhBytes,
			}
			got := mp.GetNextHop()
			if !strings.Contains(got, tt.want) {
				t.Errorf("GetNextHop() = %q, want to contain %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MPReachNLRI getter not-found paths
// ---------------------------------------------------------------------------

func TestMPReachNLRI_NLRINotFound(t *testing.T) {
	// Use AFI=1/SAFI=1 so none of the specialised getters match.
	mp := &MPReachNLRI{
		AddressFamilyID:    1,
		SubAddressFamilyID: 1,
		NLRI:               []byte{},
		addPath:            map[int]bool{},
	}

	notFound := &NLRINotFoundError{}

	t.Run("GetNLRI71 wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRI71()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRI73 wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRI73()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRIL3VPN wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIL3VPN()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRIEVPN wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIEVPN()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRIVPLS wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIVPLS()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRIMulticast wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIMulticast()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRILU wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRILU()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRIMCASTVPN wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIMCASTVPN()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRIMVPN wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIMVPN()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRIRTC wrong SAFI", func(t *testing.T) {
		_, err := mp.GetNLRIRTC()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError, got %T: %v", err, err)
		}
	})
}

// ---------------------------------------------------------------------------
// MPReachNLRI.GetFlowspecNLRI stubs
// ---------------------------------------------------------------------------

func TestMPReachNLRI_GetFlowspecNLRI_Stubs(t *testing.T) {
	tests := []struct {
		name         string
		afi          uint16
		safi         uint8
		wantErrMsg   string
		wantNotFound bool
	}{
		{
			name:       "AFI=2 SAFI=133 not implemented",
			afi:        2,
			safi:       133,
			wantErrMsg: "not yet implemented",
		},
		{
			name:       "AFI=1 SAFI=134 VPN not implemented",
			afi:        1,
			safi:       134,
			wantErrMsg: "not yet implemented",
		},
		{
			name:         "unknown SAFI returns NLRINotFoundError",
			afi:          1,
			safi:         200,
			wantNotFound: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MPReachNLRI{
				AddressFamilyID:    tt.afi,
				SubAddressFamilyID: tt.safi,
				NLRI:               []byte{},
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
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MPReachNLRI.GetNLRIUnicast – match path
// ---------------------------------------------------------------------------

func TestMPReachNLRI_GetNLRIUnicast_match(t *testing.T) {
	// 10.10.10.0/24 as unicast prefix bytes
	mp := &MPReachNLRI{
		AddressFamilyID:    1,
		SubAddressFamilyID: 1,
		NLRI:               []byte{0x18, 0x0A, 0x0A, 0x0A},
		addPath:            map[int]bool{},
	}
	nlri, err := mp.GetNLRIUnicast()
	if err != nil {
		t.Fatalf("GetNLRIUnicast() unexpected error: %v", err)
	}
	if nlri == nil {
		t.Fatal("GetNLRIUnicast() returned nil")
	}
}
