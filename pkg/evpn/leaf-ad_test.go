package evpn

import (
	"bytes"
	"testing"
)

func TestUnmarshalEVPNLeafAD_Valid(t *testing.T) {
	tests := []struct {
		name              string
		input             []byte
		wantRouteKeyLen   int
		wantOriginatorLen uint8
		wantOriginatorIP  []byte
	}{
		{
			name: "IPv4 originator with minimal route key",
			input: []byte{
				// Route Key (1 byte - minimal embedded NLRI)
				0x01,
				// Originator Address Length (1 byte) = 32 bits
				32,
				// Originator Address (4 bytes) - 192.0.2.1
				192, 0, 2, 1,
			},
			wantRouteKeyLen:   1,
			wantOriginatorLen: 32,
			wantOriginatorIP:  []byte{192, 0, 2, 1},
		},
		{
			name: "IPv4 originator with Type 3 IMET route key",
			input: []byte{
				// Route Key - Type 3 IMET A-D route (RD + EthTag + IPLen + IP)
				// RD (8 bytes)
				0, 0, 0, 100, 0, 0, 0, 200,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 0,
				// IP Address Length (1 byte) = 32 bits
				32,
				// IP Address (4 bytes) - 198.51.100.1
				198, 51, 100, 1,
				// Originator Address Length (1 byte) = 32 bits
				32,
				// Originator Address (4 bytes) - 192.0.2.1
				192, 0, 2, 1,
			},
			wantRouteKeyLen:   17, // 8 + 4 + 1 + 4
			wantOriginatorLen: 32,
			wantOriginatorIP:  []byte{192, 0, 2, 1},
		},
		{
			name: "IPv6 originator with minimal route key",
			input: []byte{
				// Route Key (1 byte - minimal embedded NLRI)
				0x01,
				// Originator Address Length (1 byte) = 128 bits
				128,
				// Originator Address (16 bytes) - 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			},
			wantRouteKeyLen:   1,
			wantOriginatorLen: 128,
			wantOriginatorIP:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name: "IPv6 originator with Type 9 Per-Region I-PMSI route key",
			input: []byte{
				// Route Key - Type 9 Per-Region I-PMSI A-D route (20 bytes)
				// RD (8 bytes)
				0, 0, 0, 100, 0, 0, 0, 200,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 1,
				// Region ID (8 bytes)
				0, 0, 0, 0, 0, 0, 0, 10,
				// Originator Address Length (1 byte) = 128 bits
				128,
				// Originator Address (16 bytes) - 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			},
			wantRouteKeyLen:   20,
			wantOriginatorLen: 128,
			wantOriginatorIP:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name: "IPv4 originator with large route key",
			input: append(
				// Route Key (100 bytes of test data)
				bytes.Repeat([]byte{0xAA}, 100),
				// Originator Address Length (1 byte) = 32 bits
				32,
				// Originator Address (4 bytes) - 203.0.113.1
				203, 0, 113, 1,
			),
			wantRouteKeyLen:   100,
			wantOriginatorLen: 32,
			wantOriginatorIP:  []byte{203, 0, 113, 1},
		},
		{
			name: "IPv6 originator with large route key",
			input: append(
				// Route Key (100 bytes of test data)
				bytes.Repeat([]byte{0xBB}, 100),
				// Originator Address Length (1 byte) = 128 bits
				128,
				// Originator Address (16 bytes) - 2001:db8::2
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			),
			wantRouteKeyLen:   100,
			wantOriginatorLen: 128,
			wantOriginatorIP:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNLeafAD(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalEVPNLeafAD() error = %v, want nil", err)
			}

			// Verify Route Key length
			if len(got.RouteKey) != tt.wantRouteKeyLen {
				t.Errorf("RouteKey length = %d, want %d", len(got.RouteKey), tt.wantRouteKeyLen)
			}

			// Verify Route Key content
			if !bytes.Equal(got.RouteKey, tt.input[0:tt.wantRouteKeyLen]) {
				t.Errorf("RouteKey content mismatch")
			}

			// Verify Originator Address Length
			if got.OriginatorAddrLen != tt.wantOriginatorLen {
				t.Errorf("OriginatorAddrLen = %d, want %d", got.OriginatorAddrLen, tt.wantOriginatorLen)
			}

			// Verify Originator Address
			if !bytes.Equal(got.OriginatorAddr, tt.wantOriginatorIP) {
				t.Errorf("OriginatorAddr = %v, want %v", got.OriginatorAddr, tt.wantOriginatorIP)
			}

			// Verify interface implementation returns correct object
			if got.GetRouteTypeSpec() != got {
				t.Errorf("GetRouteTypeSpec() should return self")
			}
		})
	}
}

func TestUnmarshalEVPNLeafAD_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		errContains string
	}{
		{
			name:        "empty input",
			input:       []byte{},
			errContains: "invalid length",
		},
		{
			name:        "too short - only 1 byte",
			input:       []byte{0x01},
			errContains: "invalid length",
		},
		{
			name:        "too short - only 5 bytes",
			input:       []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			errContains: "invalid length",
		},
		{
			name: "invalid originator length - not 32 or 128",
			input: []byte{
				// Route Key (1 byte)
				0x01,
				// Originator Address Length (1 byte) = 64 (invalid)
				64,
				// Originator Address (4 bytes)
				192, 0, 2, 1,
			},
			errContains: "invalid originator address length",
		},
		{
			name: "invalid originator length - zero",
			input: []byte{
				// Route Key (1 byte)
				0x01,
				// Originator Address Length (1 byte) = 0 (invalid)
				0,
				// Originator Address (4 bytes)
				192, 0, 2, 1,
			},
			errContains: "invalid originator address length",
		},
		{
			name: "invalid originator length - 16 instead of 32",
			input: []byte{
				// Route Key (1 byte)
				0x01,
				// Originator Address Length (1 byte) = 16 (invalid)
				16,
				// Originator Address (4 bytes)
				192, 0, 2, 1,
			},
			errContains: "invalid originator address length",
		},
		{
			name: "truncated IPv4 originator - missing address bytes",
			input: []byte{
				// Route Key (1 byte)
				0x01,
				// Originator Address Length (1 byte) = 32
				32,
				// Originator Address (only 2 bytes instead of 4) - TRUNCATED
				192, 0,
			},
			errContains: "invalid length",
		},
		{
			name: "truncated IPv6 originator - missing address bytes",
			input: []byte{
				// Route Key (1 byte)
				0x01,
				// Originator Address Length (1 byte) = 128
				128,
				// Originator Address (only 8 bytes instead of 16) - TRUNCATED
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
			},
			errContains: "invalid originator address length",
		},
		{
			name: "buffer too short for IPv6 check",
			input: []byte{
				// Only 16 bytes total - not enough for IPv6 (needs 17+)
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
			errContains: "invalid originator address length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNLeafAD(tt.input)
			if err == nil {
				t.Fatalf("UnmarshalEVPNLeafAD() succeeded with result %+v, want error containing %q", got, tt.errContains)
			}
			if tt.errContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
				t.Errorf("error = %v, want error containing %q", err, tt.errContains)
			}
		})
	}
}

func TestLeafAD_InterfaceMethods(t *testing.T) {
	l := &LeafAD{
		RouteKey:          []byte{0x01, 0x02, 0x03},
		OriginatorAddrLen: 32,
		OriginatorAddr:    []byte{192, 0, 2, 1},
	}

	// Test all interface methods return expected nil values
	if rd := l.getRD(); rd != "" {
		t.Errorf("getRD() = %q, want empty string", rd)
	}
	if esi := l.getESI(); esi != nil {
		t.Errorf("getESI() = %v, want nil", esi)
	}
	if tag := l.getTag(); tag != nil {
		t.Errorf("getTag() = %v, want nil", tag)
	}
	if mac := l.getMAC(); mac != nil {
		t.Errorf("getMAC() = %v, want nil", mac)
	}
	if macLen := l.getMACLength(); macLen != nil {
		t.Errorf("getMACLength() = %v, want nil", macLen)
	}
	if ip := l.getIPAddress(); ip != nil {
		t.Errorf("getIPAddress() = %v, want nil", ip)
	}
	if ipLen := l.getIPLength(); ipLen != nil {
		t.Errorf("getIPLength() = %v, want nil", ipLen)
	}
	if gw := l.getGWAddress(); gw != nil {
		t.Errorf("getGWAddress() = %v, want nil", gw)
	}
	if labels := l.getLabel(); labels != nil {
		t.Errorf("getLabel() = %v, want nil", labels)
	}
}
