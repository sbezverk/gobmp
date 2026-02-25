package evpn

import (
	"bytes"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalEVPNMcastLeave_Valid(t *testing.T) {
	tests := []struct {
		name              string
		input             []byte
		wantRD            string
		wantESI           *ESI
		wantEthTag        []byte
		wantMcastSrcLen   uint8
		wantMcastSrcAddr  []byte
		wantMcastGrpLen   uint8
		wantMcastGrpAddr  []byte
		wantOriginatorLen uint8
		wantOriginatorIP  []byte
		wantReserved      []byte
		wantMaxRespTime   uint8
		wantFlags         uint8
	}{
		{
			name: "IPv4 (*,G) with all zeros",
			input: []byte{
				// RD (8 bytes) - Type 0: 0:0:0
				0, 0, 0, 0, 0, 0, 0, 0,
				// ESI (10 bytes) - all zeros
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				// Ethernet Tag (4 bytes) - 0
				0, 0, 0, 0,
				// Multicast Source Length (1 byte) - 0 (wildcard)
				0,
				// Multicast Group Length (1 byte) - 32 bits
				32,
				// Multicast Group Address (4 bytes) - 224.0.0.0
				224, 0, 0, 0,
				// Originator Router Length (1 byte) - 32 bits
				32,
				// Originator Router Address (4 bytes) - 0.0.0.0
				0, 0, 0, 0,
				// Reserved (4 bytes)
				0, 0, 0, 0,
				// Maximum Response Time (1 byte)
				0,
				// Flags (1 byte)
				0,
			},
			wantRD:  "0:0",
			wantESI: func() *ESI {
				esi, _ := MakeESI([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
				return esi
			}(),
			wantEthTag:        []byte{0, 0, 0, 0},
			wantMcastSrcLen:   0,
			wantMcastSrcAddr:  nil,
			wantMcastGrpLen:   32,
			wantMcastGrpAddr:  []byte{224, 0, 0, 0},
			wantOriginatorLen: 32,
			wantOriginatorIP:  []byte{0, 0, 0, 0},
			wantReserved:      []byte{0, 0, 0, 0},
			wantMaxRespTime:   0,
			wantFlags:         0,
		},
		{
			name: "IPv4 (S,G) leave with max response time",
			input: []byte{
				// RD (8 bytes) - Type 0: 100:200
				0, 0, 0, 100, 0, 0, 0, 200,
				// ESI (10 bytes)
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
				// Ethernet Tag (4 bytes) - 100
				0, 0, 0, 100,
				// Multicast Source Length (1 byte) - 32 bits
				32,
				// Multicast Source Address (4 bytes) - 198.51.100.1
				198, 51, 100, 1,
				// Multicast Group Length (1 byte) - 32 bits
				32,
				// Multicast Group Address (4 bytes) - 239.1.1.1
				239, 1, 1, 1,
				// Originator Router Length (1 byte) - 32 bits
				32,
				// Originator Router Address (4 bytes) - 192.0.2.1
				192, 0, 2, 1,
				// Reserved (4 bytes)
				0, 0, 0, 0,
				// Maximum Response Time (1 byte) - 10 seconds
				10,
				// Flags (1 byte) - IE bit set (0x02)
				0x02,
			},
			wantRD: "100:200",
			wantESI: func() *ESI {
				esi, _ := MakeESI([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a})
				return esi
			}(),
			wantEthTag:        []byte{0, 0, 0, 100},
			wantMcastSrcLen:   32,
			wantMcastSrcAddr:  []byte{198, 51, 100, 1},
			wantMcastGrpLen:   32,
			wantMcastGrpAddr:  []byte{239, 1, 1, 1},
			wantOriginatorLen: 32,
			wantOriginatorIP:  []byte{192, 0, 2, 1},
			wantReserved:      []byte{0, 0, 0, 0},
			wantMaxRespTime:   10,
			wantFlags:         0x02,
		},
		{
			name: "IPv6 (*,G) with flags",
			input: []byte{
				// RD (8 bytes) - Type 1: 192.0.2.1:100
				0, 1, 192, 0, 2, 1, 0, 100,
				// ESI (10 bytes) - all zeros
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				// Ethernet Tag (4 bytes) - 0
				0, 0, 0, 0,
				// Multicast Source Length (1 byte) - 0 (wildcard)
				0,
				// Multicast Group Length (1 byte) - 128 bits
				128,
				// Multicast Group Address (16 bytes) - ff0e::1
				0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				// Originator Router Length (1 byte) - 128 bits
				128,
				// Originator Router Address (16 bytes) - 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				// Reserved (4 bytes)
				0xaa, 0xbb, 0xcc, 0xdd,
				// Maximum Response Time (1 byte)
				5,
				// Flags (1 byte) - V bit set (0x01)
				0x01,
			},
			wantRD: "192.0.2.1:100",
			wantESI: func() *ESI {
				esi, _ := MakeESI([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
				return esi
			}(),
			wantEthTag:        []byte{0, 0, 0, 0},
			wantMcastSrcLen:   0,
			wantMcastSrcAddr:  nil,
			wantMcastGrpLen:   128,
			wantMcastGrpAddr:  []byte{0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			wantOriginatorLen: 128,
			wantOriginatorIP:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			wantReserved:      []byte{0xaa, 0xbb, 0xcc, 0xdd},
			wantMaxRespTime:   5,
			wantFlags:         0x01,
		},
		{
			name: "IPv6 (S,G) with non-zero ESI",
			input: []byte{
				// RD (8 bytes)
				0, 1, 192, 0, 2, 1, 0, 100,
				// ESI (10 bytes) - non-zero
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
				// Ethernet Tag (4 bytes)
				0, 0, 1, 0,
				// Multicast Source Length (1 byte) - 128 bits
				128,
				// Multicast Source Address (16 bytes) - 2001:db8::100
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
				// Multicast Group Length (1 byte) - 128 bits
				128,
				// Multicast Group Address (16 bytes) - ff0e::1:1
				0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
				// Originator Router Length (1 byte) - 128 bits
				128,
				// Originator Router Address (16 bytes) - 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				// Reserved (4 bytes)
				0, 0, 0, 0,
				// Maximum Response Time (1 byte)
				20,
				// Flags (1 byte) - both V and IE bits (0x03)
				0x03,
			},
			wantRD: "192.0.2.1:100",
			wantESI: func() *ESI {
				esi, _ := MakeESI([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99})
				return esi
			}(),
			wantEthTag:        []byte{0, 0, 1, 0},
			wantMcastSrcLen:   128,
			wantMcastSrcAddr:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
			wantMcastGrpLen:   128,
			wantMcastGrpAddr:  []byte{0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1},
			wantOriginatorLen: 128,
			wantOriginatorIP:  []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			wantReserved:      []byte{0, 0, 0, 0},
			wantMaxRespTime:   20,
			wantFlags:         0x03,
		},
		{
			name: "Mixed IPv4 source and IPv6 group",
			input: []byte{
				// RD (8 bytes)
				0, 0, 0, 100, 0, 0, 0, 200,
				// ESI (10 bytes)
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 0,
				// Multicast Source Length (1 byte) - 32 bits
				32,
				// Multicast Source Address (4 bytes) - 198.51.100.1
				198, 51, 100, 1,
				// Multicast Group Length (1 byte) - 128 bits
				128,
				// Multicast Group Address (16 bytes) - ff0e::1
				0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				// Originator Router Length (1 byte) - 32 bits
				32,
				// Originator Router Address (4 bytes) - 192.0.2.1
				192, 0, 2, 1,
				// Reserved (4 bytes)
				0xff, 0xff, 0xff, 0xff,
				// Maximum Response Time (1 byte)
				255,
				// Flags (1 byte)
				0xff,
			},
			wantRD: "100:200",
			wantESI: func() *ESI {
				esi, _ := MakeESI([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
				return esi
			}(),
			wantEthTag:        []byte{0, 0, 0, 0},
			wantMcastSrcLen:   32,
			wantMcastSrcAddr:  []byte{198, 51, 100, 1},
			wantMcastGrpLen:   128,
			wantMcastGrpAddr:  []byte{0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			wantOriginatorLen: 32,
			wantOriginatorIP:  []byte{192, 0, 2, 1},
			wantReserved:      []byte{0xff, 0xff, 0xff, 0xff},
			wantMaxRespTime:   255,
			wantFlags:         0xff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNMcastLeave(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalEVPNMcastLeave() error = %v, want nil", err)
			}

			// Verify RD
			if gotRD := got.getRD(); gotRD != tt.wantRD {
				t.Errorf("RD = %s, want %s", gotRD, tt.wantRD)
			}

			// Verify ESI
			if !bytes.Equal(got.ESI[:], tt.wantESI[:]) {
				t.Errorf("ESI = %v, want %v", got.ESI, tt.wantESI)
			}

			// Verify Ethernet Tag
			if !bytes.Equal(got.EthTag, tt.wantEthTag) {
				t.Errorf("EthTag = %v, want %v", got.EthTag, tt.wantEthTag)
			}

			// Verify Multicast Source
			if got.McastSrcLen != tt.wantMcastSrcLen {
				t.Errorf("McastSrcLen = %d, want %d", got.McastSrcLen, tt.wantMcastSrcLen)
			}
			if !bytes.Equal(got.McastSrcAddr, tt.wantMcastSrcAddr) {
				t.Errorf("McastSrcAddr = %v, want %v", got.McastSrcAddr, tt.wantMcastSrcAddr)
			}

			// Verify Multicast Group
			if got.McastGrpLen != tt.wantMcastGrpLen {
				t.Errorf("McastGrpLen = %d, want %d", got.McastGrpLen, tt.wantMcastGrpLen)
			}
			if !bytes.Equal(got.McastGrpAddr, tt.wantMcastGrpAddr) {
				t.Errorf("McastGrpAddr = %v, want %v", got.McastGrpAddr, tt.wantMcastGrpAddr)
			}

			// Verify Originator Router
			if got.OriginatorRtrLen != tt.wantOriginatorLen {
				t.Errorf("OriginatorRtrLen = %d, want %d", got.OriginatorRtrLen, tt.wantOriginatorLen)
			}
			if !bytes.Equal(got.OriginatorRtrAddr, tt.wantOriginatorIP) {
				t.Errorf("OriginatorRtrAddr = %v, want %v", got.OriginatorRtrAddr, tt.wantOriginatorIP)
			}

			// Verify Reserved field
			if !bytes.Equal(got.Reserved, tt.wantReserved) {
				t.Errorf("Reserved = %v, want %v", got.Reserved, tt.wantReserved)
			}

			// Verify Maximum Response Time
			if got.MaxResponseTime != tt.wantMaxRespTime {
				t.Errorf("MaxResponseTime = %d, want %d", got.MaxResponseTime, tt.wantMaxRespTime)
			}

			// Verify Flags
			if got.Flags != tt.wantFlags {
				t.Errorf("Flags = 0x%02x, want 0x%02x", got.Flags, tt.wantFlags)
			}

			// Verify interface implementation
			if got.GetRouteTypeSpec() != got {
				t.Errorf("GetRouteTypeSpec() should return self")
			}
		})
	}
}

func TestUnmarshalEVPNMcastLeave_Invalid(t *testing.T) {
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
			name:        "too short - minimum length not met",
			input:       bytes.Repeat([]byte{0}, 38),
			errContains: "invalid length",
		},
		{
			name: "invalid multicast source length",
			input: []byte{
				// RD (8 bytes)
				0, 0, 0, 0, 0, 0, 0, 0,
				// ESI (10 bytes)
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 0,
				// Multicast Source Length (1 byte) - INVALID: 64
				64,
				// Multicast Group Length (1 byte)
				32,
				// Multicast Group Address (4 bytes)
				224, 0, 0, 0,
				// Originator Router Length (1 byte)
				32,
				// Originator Router Address (4 bytes)
				0, 0, 0, 0,
				// Reserved (4 bytes)
				0, 0, 0, 0,
				// Maximum Response Time (1 byte)
				0,
				// Flags (1 byte)
				0,
			},
			errContains: "invalid multicast source length",
		},
		{
			name: "invalid multicast group length",
			input: []byte{
				// RD (8 bytes)
				0, 0, 0, 0, 0, 0, 0, 0,
				// ESI (10 bytes)
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 0,
				// Multicast Source Length (1 byte)
				0,
				// Multicast Group Length (1 byte) - INVALID: 64
				64,
				// Multicast Group Address (4 bytes)
				224, 0, 0, 0,
				// Originator Router Length (1 byte)
				32,
				// Originator Router Address (4 bytes)
				0, 0, 0, 0,
				// Reserved (4 bytes)
				0, 0, 0, 0,
				// Maximum Response Time (1 byte)
				0,
				// Flags (1 byte)
				0,
			},
			errContains: "invalid multicast group length",
		},
		{
			name: "invalid originator router length",
			input: []byte{
				// RD (8 bytes)
				0, 0, 0, 0, 0, 0, 0, 0,
				// ESI (10 bytes)
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 0,
				// Multicast Source Length (1 byte)
				0,
				// Multicast Group Length (1 byte)
				32,
				// Multicast Group Address (4 bytes)
				224, 0, 0, 0,
				// Originator Router Length (1 byte) - INVALID: 64
				64,
				// Originator Router Address (4 bytes)
				0, 0, 0, 0,
				// Reserved (4 bytes)
				0, 0, 0, 0,
				// Maximum Response Time (1 byte)
				0,
				// Flags (1 byte)
				0,
			},
			errContains: "invalid originator router length",
		},
		{
			name: "truncated at reserved field",
			input: []byte{
				// RD (8 bytes)
				0, 0, 0, 0, 0, 0, 0, 0,
				// ESI (10 bytes)
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 0,
				// Multicast Source Length (1 byte)
				0,
				// Multicast Group Length (1 byte)
				32,
				// Multicast Group Address (4 bytes)
				224, 0, 0, 0,
				// Originator Router Length (1 byte)
				32,
				// Originator Router Address (4 bytes)
				0, 0, 0, 0,
				// Reserved (only 2 bytes instead of 4) - TRUNCATED
				0, 0,
			},
			errContains: "invalid length",
		},
		{
			name: "truncated at maximum response time",
			input: []byte{
				// RD (8 bytes)
				0, 0, 0, 0, 0, 0, 0, 0,
				// ESI (10 bytes)
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 0,
				// Multicast Source Length (1 byte)
				0,
				// Multicast Group Length (1 byte)
				32,
				// Multicast Group Address (4 bytes)
				224, 0, 0, 0,
				// Originator Router Length (1 byte)
				32,
				// Originator Router Address (4 bytes)
				0, 0, 0, 0,
				// Reserved (4 bytes)
				0, 0, 0, 0,
				// Maximum Response Time - MISSING
			},
			errContains: "invalid length",
		},
		{
			name: "truncated at flags",
			input: []byte{
				// RD (8 bytes)
				0, 0, 0, 0, 0, 0, 0, 0,
				// ESI (10 bytes)
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 0,
				// Multicast Source Length (1 byte)
				0,
				// Multicast Group Length (1 byte)
				32,
				// Multicast Group Address (4 bytes)
				224, 0, 0, 0,
				// Originator Router Length (1 byte)
				32,
				// Originator Router Address (4 bytes)
				0, 0, 0, 0,
				// Reserved (4 bytes)
				0, 0, 0, 0,
				// Maximum Response Time (1 byte)
				0,
				// Flags - MISSING
			},
			errContains: "invalid length",
		},
		{
			name: "extra bytes after flags",
			input: []byte{
				// RD (8 bytes)
				0, 0, 0, 0, 0, 0, 0, 0,
				// ESI (10 bytes)
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				// Ethernet Tag (4 bytes)
				0, 0, 0, 0,
				// Multicast Source Length (1 byte)
				0,
				// Multicast Group Length (1 byte)
				32,
				// Multicast Group Address (4 bytes)
				224, 0, 0, 0,
				// Originator Router Length (1 byte)
				32,
				// Originator Router Address (4 bytes)
				0, 0, 0, 0,
				// Reserved (4 bytes)
				0, 0, 0, 0,
				// Maximum Response Time (1 byte)
				0,
				// Flags (1 byte)
				0,
				// EXTRA bytes
				0xff, 0xff,
			},
			errContains: "invalid length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalEVPNMcastLeave(tt.input)
			if err == nil {
				t.Fatalf("UnmarshalEVPNMcastLeave() succeeded with result %+v, want error containing %q", got, tt.errContains)
			}
			if tt.errContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
				t.Errorf("error = %v, want error containing %q", err, tt.errContains)
			}
		})
	}
}

func TestMcastLeave_InterfaceMethods(t *testing.T) {
	rd, _ := base.MakeRD([]byte{0, 0, 0, 100, 0, 0, 0, 200})
	esi, _ := MakeESI([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a})

	m := &McastLeave{
		RD:                rd,
		ESI:               esi,
		EthTag:            []byte{0, 0, 0, 1},
		McastSrcLen:       32,
		McastSrcAddr:      []byte{198, 51, 100, 1},
		McastGrpLen:       32,
		McastGrpAddr:      []byte{239, 1, 1, 1},
		OriginatorRtrLen:  32,
		OriginatorRtrAddr: []byte{192, 0, 2, 1},
		Reserved:          []byte{0, 0, 0, 0},
		MaxResponseTime:   10,
		Flags:             0x02,
	}

	// Test interface methods return expected values
	if rd := m.getRD(); rd != "100:200" {
		t.Errorf("getRD() = %s, want 100:200", rd)
	}
	if gotESI := m.getESI(); !bytes.Equal(gotESI[:], esi[:]) {
		t.Errorf("getESI() = %v, want %v", gotESI, esi)
	}
	if tag := m.getTag(); !bytes.Equal(tag, []byte{0, 0, 0, 1}) {
		t.Errorf("getTag() = %v, want [0 0 0 1]", tag)
	}

	// Test all nil-returning interface methods
	if mac := m.getMAC(); mac != nil {
		t.Errorf("getMAC() = %v, want nil", mac)
	}
	if macLen := m.getMACLength(); macLen != nil {
		t.Errorf("getMACLength() = %v, want nil", macLen)
	}
	if ip := m.getIPAddress(); ip != nil {
		t.Errorf("getIPAddress() = %v, want nil", ip)
	}
	if ipLen := m.getIPLength(); ipLen != nil {
		t.Errorf("getIPLength() = %v, want nil", ipLen)
	}
	if gw := m.getGWAddress(); gw != nil {
		t.Errorf("getGWAddress() = %v, want nil", gw)
	}
	if labels := m.getLabel(); labels != nil {
		t.Errorf("getLabel() = %v, want nil", labels)
	}
}
