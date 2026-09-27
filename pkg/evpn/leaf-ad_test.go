package evpn

import (
	"bytes"
	"testing"
)

// imetRouteKey builds a conforming EVPN Route Key: the full embedded NLRI
// (Type(1) + Length(1) + Value) of an Inclusive Multicast Ethernet Tag
// (Type 3 / IMET) route -- one of the PMSI routes that RFC 9572 Section 3.3
// says triggers a Leaf A-D route. rdLastOctet lets tests control the last
// byte of the RD's embedded IPv4 address (used for the RD/originator
// collision counterexample).
func imetRouteKey(rdLastOctet byte) []byte {
	return []byte{
		3, 17, // Route Key header: Type=3 (IMET), Length=17
		0, 1, 10, 0, 0, rdLastOctet, 0, 1, // RD: Type 1, IP 10.0.0.<rdLastOctet>, assigned number 1
		0, 0, 0, 0, // Ethernet Tag
		32,          // IP Address Length
		10, 1, 1, 1, // IP Address
	}
}

func TestUnmarshalEVPNLeafAD_Valid(t *testing.T) {
	tests := []struct {
		name              string
		input             []byte
		wantRouteKeyLen   int
		wantOriginatorLen uint8
		wantOriginatorIP  []byte
	}{
		{
			// Smallest Route Key the parser accepts: just the Type+Length
			// header with a zero-length value (2 bytes total). Not a valid
			// EVPN route; it exercises the forward-parse boundary.
			name: "IPv4 originator with minimal (2-byte header) route key",
			input: []byte{
				0x01, 0x00, // Route Key: Type=1, Length=0 (no value)
				32,           // Originator's Addr Length = 32 bits
				192, 0, 2, 1, // Originator's Addr - 192.0.2.1
			},
			wantRouteKeyLen:   2,
			wantOriginatorLen: 32,
			wantOriginatorIP:  []byte{192, 0, 2, 1},
		},
		{
			name: "IPv4 originator with IMET route key",
			input: append(
				imetRouteKey(200),
				append([]byte{32}, []byte{198, 51, 100, 1}...)...,
			),
			wantRouteKeyLen:   19,
			wantOriginatorLen: 32,
			wantOriginatorIP:  []byte{198, 51, 100, 1},
		},
		{
			name: "IPv6 originator with minimal (2-byte header) route key",
			input: []byte{
				0x01, 0x00, // Route Key: Type=1, Length=0 (no value)
				128,                                                        // Originator's Addr Length = 128 bits
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // 2001:db8::1
			},
			wantRouteKeyLen:   2,
			wantOriginatorLen: 128,
			wantOriginatorIP:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name: "IPv6 originator with Type 9 Per-Region I-PMSI route key",
			input: []byte{
				9, 20, // Route Key header: Type=9 (Per-Region I-PMSI A-D), Length=20
				// RD (8 bytes): Type 1, 10.0.0.100, assigned number 200
				0, 1, 10, 0, 0, 100, 0, 200,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 1,
				// Region ID (8 bytes)
				0, 0, 0, 0, 0, 0, 0, 10,
				// Originator's Addr Length (1 byte) = 128 bits
				128,
				// Originator's Addr (16 bytes) - 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			},
			wantRouteKeyLen:   22,
			wantOriginatorLen: 128,
			wantOriginatorIP:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			// Route Key is a large embedded NLRI (Type/Length header framing
			// a 100-byte value); only the 2-byte header is inspected by the
			// parser, so the value content is immaterial.
			name: "IPv4 originator with large route key",
			input: append(
				append([]byte{7, 100}, bytes.Repeat([]byte{0xAA}, 100)...),
				append([]byte{32}, []byte{203, 0, 113, 1}...)...,
			),
			wantRouteKeyLen:   102,
			wantOriginatorLen: 32,
			wantOriginatorIP:  []byte{203, 0, 113, 1},
		},
		{
			name: "IPv6 originator with large route key",
			input: append(
				append([]byte{7, 100}, bytes.Repeat([]byte{0xBB}, 100)...),
				append([]byte{128}, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}...)...,
			),
			wantRouteKeyLen:   102,
			wantOriginatorLen: 128,
			wantOriginatorIP:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		},
		{
			// RFC 9572 AF-5 counterexample: Route Key = IMET route whose RD
			// carries IPv4 10.0.0.128 (last octet 0x80/128), immediately
			// followed by an IPv4 (32-bit) originator. Backward parsing
			// (unmodified code) reads b[len-17]==128 and misreads this as a
			// 128-bit IPv6 originator with a 7-byte truncated Route Key.
			// Forward parsing (this fix) must decode the IPv4 originator
			// 2.2.2.2 and the full 19-byte Route Key.
			name: "RD last octet 0x80 does not misdetect IPv6 originator",
			input: append(
				imetRouteKey(128),
				append([]byte{32}, []byte{2, 2, 2, 2}...)...,
			),
			wantRouteKeyLen:   19,
			wantOriginatorLen: 32,
			wantOriginatorIP:  []byte{2, 2, 2, 2},
		},
		{
			// Mirror case: a conforming Route Key whose IPv6 originator
			// address happens to contain byte 0x20 (32) at address[11]
			// (i.e. buffer offset len(b)-5). Backward parsing tries the
			// IPv4 branch only if the IPv6 branch fails first, and here the
			// IPv6 branch correctly matches -- this asserts forward parsing
			// gives the same (correct) result, not a false IPv4 match.
			name: "IPv6 originator with 0x20 at offset len-5 does not misdetect IPv4",
			input: append(
				imetRouteKey(200),
				append([]byte{128}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 32, 11, 12, 13, 14, 15}...)...,
			),
			wantRouteKeyLen:   19,
			wantOriginatorLen: 128,
			wantOriginatorIP:  []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 32, 11, 12, 13, 14, 15},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNLeafAD(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalEVPNLeafAD() error = %v, want nil", err)
			}

			if len(got.RouteKey) != tt.wantRouteKeyLen {
				t.Errorf("RouteKey length = %d, want %d", len(got.RouteKey), tt.wantRouteKeyLen)
			}
			if !bytes.Equal(got.RouteKey, tt.input[0:tt.wantRouteKeyLen]) {
				t.Errorf("RouteKey content mismatch: got %v, want %v", got.RouteKey, tt.input[0:tt.wantRouteKeyLen])
			}
			if got.OriginatorAddrLen != tt.wantOriginatorLen {
				t.Errorf("OriginatorAddrLen = %d, want %d", got.OriginatorAddrLen, tt.wantOriginatorLen)
			}
			if !bytes.Equal(got.OriginatorAddr, tt.wantOriginatorIP) {
				t.Errorf("OriginatorAddr = %v, want %v", got.OriginatorAddr, tt.wantOriginatorIP)
			}
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
			name:        "too short - only 1 byte, no room for Route Key header",
			input:       []byte{0x01},
			errContains: "invalid length",
		},
		{
			name: "Route Key length byte exceeds remaining buffer",
			input: []byte{
				3, 200, // Route Key header claims Length=200
				0, 1, 10, 0, 0, 200, // but only a handful of bytes follow
			},
			errContains: "invalid length",
		},
		{
			name: "Route Key consumes entire buffer, no Originator's Addr Length byte",
			input: []byte{
				0x01, 0x02, 0xAA, 0xBB, // Type=1, Length=2, value = AA BB
			},
			errContains: "missing Originator's Addr Length byte",
		},
		{
			name: "invalid originator length - not 32 or 128",
			input: append(
				imetRouteKey(200),
				append([]byte{64}, []byte{192, 0, 2, 1}...)...,
			),
			errContains: "invalid originator address length",
		},
		{
			name: "invalid originator length - zero",
			input: append(
				imetRouteKey(200),
				append([]byte{0}, []byte{192, 0, 2, 1}...)...,
			),
			errContains: "invalid originator address length",
		},
		{
			name: "invalid originator length - 16 instead of 32",
			input: append(
				imetRouteKey(200),
				append([]byte{16}, []byte{192, 0, 2, 1}...)...,
			),
			errContains: "invalid originator address length",
		},
		{
			name: "mismatched length - IPv4 originator length byte but only 2 bytes remain",
			input: append(
				imetRouteKey(200),
				append([]byte{32}, []byte{192, 0}...)...,
			),
			errContains: "requires 4 bytes, have 2",
		},
		{
			name: "mismatched length - IPv4 originator length byte but 5 bytes remain",
			input: append(
				imetRouteKey(200),
				append([]byte{32}, []byte{192, 0, 2, 1, 0xFF}...)...,
			),
			errContains: "requires 4 bytes, have 5",
		},
		{
			name: "mismatched length - IPv6 originator length byte but only 8 bytes remain",
			input: append(
				imetRouteKey(200),
				append([]byte{128}, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0}...)...,
			),
			errContains: "requires 16 bytes, have 8",
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
