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
			wantErr: "need 1 byte for Reserved",
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
		name    string
		nhLen   uint8
		nhBytes []byte
		want    bool
	}{
		{"IPv4 4-byte", 4, nil, false},
		{"RD+IPv4 8-byte", 8, nil, false},
		{"RD+IPv4 12-byte", 12, nil, false},
		{"IPv6 16-byte", 16, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, true},
		{"IPv4-mapped-IPv6 16-byte", 16, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1}, false},
		{"RD+IPv6 24-byte", 24, nil, true},
		{"IPv6+LL 32-byte", 32, nil, true},
		{"RD+IPv6+LL 48-byte", 48, nil, true},
		{"zero length", 0, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MPReachNLRI{NextHopAddressLength: tt.nhLen, NextHopAddress: tt.nhBytes}
			if got := mp.IsNextHopIPv6(); got != tt.want {
				t.Errorf("IsNextHopIPv6() nhLen=%d = %v, want %v", tt.nhLen, got, tt.want)
			}
		})
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
			name:    "IPv4-mapped-IPv6 (len=16)",
			nhLen:   16,
			nhBytes: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1},
			want:    "10.0.0.1",
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

	// N11: Verify wrong AFI with correct SAFI is rejected
	t.Run("GetNLRI71 wrong AFI correct SAFI", func(t *testing.T) {
		mp71 := &MPReachNLRI{
			AddressFamilyID:    1, // should be 16388
			SubAddressFamilyID: 71,
			NLRI:               []byte{},
			addPath:            map[int]bool{},
		}
		_, err := mp71.GetNLRI71()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError for wrong AFI, got %T: %v", err, err)
		}
	})
	t.Run("GetNLRI73 wrong AFI correct SAFI", func(t *testing.T) {
		mp73 := &MPReachNLRI{
			AddressFamilyID:    16388, // should be 1 or 2
			SubAddressFamilyID: 73,
			NLRI:               []byte{},
			addPath:            map[int]bool{},
		}
		_, err := mp73.GetNLRI73()
		if !errors.As(err, &notFound) {
			t.Errorf("expected NLRINotFoundError for wrong AFI, got %T: %v", err, err)
		}
	})
}

// TestMPReachNLRI_GetNLRIRTC covers the AFI guard on GetNLRIRTC.
// Per RFC 4684 §4, RTC carries AFI=1 or AFI=2 with SAFI=132; any other AFI
// must return NLRINotFoundError.
func TestMPReachNLRI_GetNLRIRTC(t *testing.T) {
	tests := []struct {
		name    string
		afi     uint16
		safi    uint8
		nlri    []byte
		wantErr bool
	}{
		{
			name: "AFI=1 SAFI=132 wildcard RTC",
			afi:  1, safi: 132,
			nlri:    []byte{0x00}, // RFC 4684 §4 wildcard RTC NLRI
			wantErr: false,
		},
		{
			name: "AFI=2 SAFI=132 wildcard RTC",
			afi:  2, safi: 132,
			nlri:    []byte{0x00},
			wantErr: false,
		},
		{
			name: "wrong AFI (L2VPN) rejected",
			afi:  25, safi: 132,
			nlri:    []byte{0x00},
			wantErr: true,
		},
	}
	notFound := &NLRINotFoundError{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &MPReachNLRI{
				AddressFamilyID:    tt.afi,
				SubAddressFamilyID: tt.safi,
				NLRI:               tt.nlri,
				addPath:            map[int]bool{},
			}
			route, err := mp.GetNLRIRTC()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("AFI=%d SAFI=%d: expected error, got nil", tt.afi, tt.safi)
				}
				if !errors.As(err, &notFound) {
					t.Errorf("AFI=%d SAFI=%d: expected NLRINotFoundError, got %T: %v", tt.afi, tt.safi, err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("AFI=%d SAFI=%d: unexpected error: %v", tt.afi, tt.safi, err)
			}
			if route == nil {
				t.Fatalf("AFI=%d SAFI=%d: expected non-nil *rtc.Route", tt.afi, tt.safi)
			}
			if len(route.NLRI) != 1 {
				t.Fatalf("AFI=%d SAFI=%d: expected 1 NLRI, got %d", tt.afi, tt.safi, len(route.NLRI))
			}
			if route.NLRI[0].Length != 0 {
				t.Errorf("AFI=%d SAFI=%d: expected wildcard NLRI (Length=0), got Length=%d", tt.afi, tt.safi, route.NLRI[0].Length)
			}
		})
	}
}

// TestMPReachNLRI_GetNLRIMCASTVPN_WithData exercises the ipv6 flag path in GetNLRIMCASTVPN.
func TestMPReachNLRI_GetNLRIMCASTVPN_WithData(t *testing.T) {
	// Type 4 (Leaf A-D) with AFI=2: RD(8) + OriginatorIP(16) = 24 bytes min
	type4Data := []byte{
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, // RD 100:200
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Originator IP 2001:db8::1
	}
	nlri := []byte{0x04, byte(len(type4Data))}
	nlri = append(nlri, type4Data...)

	mp := &MPReachNLRI{
		AddressFamilyID:    2,
		SubAddressFamilyID: 5,
		NLRI:               nlri,
		addPath:            map[int]bool{},
	}
	route, err := mp.GetNLRIMCASTVPN()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(route.Route) != 1 {
		t.Fatalf("expected 1 route, got %d", len(route.Route))
	}
	origIP := route.Route[0].GetMCASTVPNOriginatorIP()
	if len(origIP) != 16 {
		t.Fatalf("expected 16-byte IPv6 originator IP, got %d bytes", len(origIP))
	}
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
			name:       "AFI=2 SAFI=133 IPv6 flowspec (empty NLRI)",
			afi:        2,
			safi:       133,
			wantErrMsg: "NLRI length is 0",
		},
		{
			name:       "AFI=1 SAFI=134 VPN empty NLRI",
			afi:        1,
			safi:       134,
			wantErrMsg: "NLRI length is 0",
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

// TestMPReachNLRI_GetFlowspecNLRI_VPNWithData verifies SAFI=134 VPN FlowSpec parse path
// with actual wire-format data.
func TestMPReachNLRI_GetFlowspecNLRI_VPNWithData(t *testing.T) {
	// VPN IPv4: RD(8) + Type1 dest prefix 10.0.0.0/8 (3 bytes) = 11 total
	mp := &MPReachNLRI{
		AddressFamilyID:    1,
		SubAddressFamilyID: 134,
		NLRI: []byte{
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
	if nlri.RD != "100:1" {
		t.Errorf("RD = %q, want %q", nlri.RD, "100:1")
	}
	if len(nlri.Spec) != 1 {
		t.Errorf("got %d specs, want 1", len(nlri.Spec))
	}
}

// TestMPReachNLRI_GetFlowspecNLRI_VPNIPv6 verifies SAFI=134 AFI=2 VPN IPv6 FlowSpec.
func TestMPReachNLRI_GetFlowspecNLRI_VPNIPv6(t *testing.T) {
	// VPN IPv6: RD(8) + Type1 IPv6 dest 2001:db8::/32 offset=0 (7 bytes) = 15 total
	mp := &MPReachNLRI{
		AddressFamilyID:    2,
		SubAddressFamilyID: 134,
		NLRI: []byte{
			0x0f,                                           // Length: 15
			0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x01, 0x2c, // RD 200:300
			0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8, // Type1 Dest 2001:db8::/32
		},
		addPath: map[int]bool{},
	}
	nlri, err := mp.GetFlowspecNLRI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.RD != "200:300" {
		t.Errorf("RD = %q, want %q", nlri.RD, "200:300")
	}
}

// ---------------------------------------------------------------------------
// MPReachNLRI.GetAllFlowspecNLRI
// ---------------------------------------------------------------------------

func TestMPReachNLRI_GetAllFlowspecNLRI(t *testing.T) {

	tests := []struct {
		name         string
		afi          uint16
		safi         uint8
		nlri         []byte
		wantCount    int
		wantErrMsg   string
		wantNotFound bool
	}{
		{
			// Valid IPv4 flowspec NLRI: 10.0.0.0/8 destination prefix
			name:      "AFI=1 SAFI=133 single IPv4 NLRI",
			afi:       1,
			safi:      133,
			nlri:      []byte{0x03, 0x01, 0x08, 0x0a},
			wantCount: 1,
		},
		{
			// Valid IPv6 flowspec NLRI: 2001:db8::/32 offset=0
			name:      "AFI=2 SAFI=133 single IPv6 NLRI",
			afi:       2,
			safi:      133,
			nlri:      []byte{0x07, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8},
			wantCount: 1,
		},
		{
			name:      "AFI=1 SAFI=134 VPN empty NLRI returns nil",
			afi:       1,
			safi:      134,
			wantCount: 0,
		},
		{
			name: "AFI=1 SAFI=134 VPN with real data",
			afi:  1,
			safi: 134,
			nlri: []byte{
				0x0b,                                           // Length: 11
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, // RD 100:1
				0x01, 0x08, 0x0a, // Type1 Dest 10.0.0.0/8
			},
			wantCount: 1,
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
				NLRI:               tt.nlri,
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
			if len(nlris) != tt.wantCount {
				t.Errorf("got %d NLRIs, want %d", len(nlris), tt.wantCount)
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

// nodeNLRI71Payload is a minimal valid BGP-LS Node NLRI (type=1) byte slice
// used by GetNLRI71 tests. It matches the RFC 7752 Node NLRI test data.
var nodeNLRI71Payload = []byte{
	0x00, 0x01, 0x00, 0x27, // type=1 (Node), length=39
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // proto=2, ident=0
	0x01, 0x00, 0x00, 0x1a, // LocalNode desc type=256, len=26
	0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, // AS=65000
	0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // BGP-LS ID=0
	0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Router-ID
}

func TestMPReachNLRI_GetNLRI71_NoAddPath(t *testing.T) {
	mp := &MPReachNLRI{
		AddressFamilyID:    16388,
		SubAddressFamilyID: 71,
		NLRI:               nodeNLRI71Payload,
		addPath:            map[int]bool{71: false},
	}
	nlri, err := mp.GetNLRI71()
	if err != nil {
		t.Fatalf("GetNLRI71() unexpected error: %v", err)
	}
	if nlri == nil || len(nlri.NLRI) == 0 {
		t.Fatal("GetNLRI71() returned nil or empty NLRI")
	}
	if nlri.NLRI[0].PathID != 0 {
		t.Errorf("expected PathID=0, got %d", nlri.NLRI[0].PathID)
	}
}

func TestMPReachNLRI_GetNLRI71_WithAddPath(t *testing.T) {
	// Prepend 4-byte Path-ID=7 before the Node NLRI payload
	payload := append([]byte{0x00, 0x00, 0x00, 0x07}, nodeNLRI71Payload...)
	mp := &MPReachNLRI{
		AddressFamilyID:    16388,
		SubAddressFamilyID: 71,
		NLRI:               payload,
		addPath:            map[int]bool{71: true},
	}
	nlri, err := mp.GetNLRI71()
	if err != nil {
		t.Fatalf("GetNLRI71() with Add Path unexpected error: %v", err)
	}
	if len(nlri.NLRI) == 0 {
		t.Fatal("GetNLRI71() with Add Path returned empty NLRI")
	}
	if nlri.NLRI[0].PathID != 7 {
		t.Errorf("expected PathID=7, got %d", nlri.NLRI[0].PathID)
	}
}
