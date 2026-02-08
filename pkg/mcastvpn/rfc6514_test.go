package mcastvpn

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// makeRD builds an 8-byte RD for test input. Type 0: 2-byte admin + 4-byte assigned.
func makeRD(admin uint16, assigned uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], 0) // RD type 0
	binary.BigEndian.PutUint16(b[2:4], admin)
	binary.BigEndian.PutUint32(b[4:8], assigned)
	return b
}

// makeRDType1 builds an 8-byte RD Type 1: 2-byte type + 4-byte IPv4 admin + 2-byte assigned.
func makeRDType1(ip [4]byte, assigned uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], 1)
	copy(b[2:6], ip[:])
	binary.BigEndian.PutUint16(b[6:8], assigned)
	return b
}

// makeRDType2 builds an 8-byte RD Type 2: 2-byte type + 4-byte 4-byte admin + 2-byte assigned.
func makeRDType2(admin uint32, assigned uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], 2)
	binary.BigEndian.PutUint32(b[2:6], admin)
	binary.BigEndian.PutUint16(b[6:8], assigned)
	return b
}

// --- RFC 6514 Section 4.1: Intra-AS I-PMSI A-D (Type 1) ---

func TestRFC6514_Type1_IPv4(t *testing.T) {
	rd := makeRD(100, 100)
	origIP := []byte{10, 0, 0, 1}
	input := append(rd, origIP...)

	got, err := UnmarshalType1(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got.OriginatorIP, origIP) {
		t.Errorf("OriginatorIP = %v, want %v", got.OriginatorIP, origIP)
	}
	if got.RD == nil {
		t.Fatal("RD is nil")
	}
}

func TestRFC6514_Type1_IPv6(t *testing.T) {
	rd := makeRD(100, 100)
	origIP := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	input := append(rd, origIP...)

	got, err := UnmarshalType1(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got.OriginatorIP, origIP) {
		t.Errorf("OriginatorIP = %v, want %v", got.OriginatorIP, origIP)
	}
}

func TestRFC6514_Type1_AllRDTypes(t *testing.T) {
	tests := []struct {
		name string
		rd   []byte
	}{
		{"RD Type 0", makeRD(100, 200)},
		{"RD Type 1", makeRDType1([4]byte{10, 0, 0, 1}, 100)},
		{"RD Type 2", makeRDType2(65000, 100)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := append(tt.rd, []byte{10, 0, 0, 1}...)
			got, err := UnmarshalType1(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.RD == nil {
				t.Fatal("RD is nil")
			}
		})
	}
}

func TestRFC6514_Type1_TooShort(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"Empty", []byte{}},
		{"7 bytes", make([]byte, 7)},
		{"11 bytes", make([]byte, 11)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalType1(tt.input)
			if err == nil {
				t.Fatal("expected error for short input")
			}
		})
	}
}

func TestRFC6514_Type1_InvalidOriginatorIPLength(t *testing.T) {
	tests := []struct {
		name      string
		ipLen     int
		errSubstr string
	}{
		// 8+3=11 < 12 minimum -> hits minimum length error
		{"3 bytes", 3, "invalid Type1 length"},
		// 8+5=13 passes minimum but 5 is not 4 or 16
		{"5 bytes", 5, "invalid originating router IP length"},
		// 8+8=16 passes minimum but 8 is not 4 or 16
		{"8 bytes", 8, "invalid originating router IP length"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd := makeRD(100, 100)
			input := append(rd, make([]byte, tt.ipLen)...)
			_, err := UnmarshalType1(input)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
			}
		})
	}
}

func TestRFC6514_Type1_InvalidRDType(t *testing.T) {
	rd := make([]byte, 8)
	binary.BigEndian.PutUint16(rd[0:2], 5) // Invalid RD type
	input := append(rd, []byte{10, 0, 0, 1}...)

	_, err := UnmarshalType1(input)
	if err == nil {
		t.Fatal("expected error for invalid RD type")
	}
}

func TestRFC6514_Type1_InterfaceMethods(t *testing.T) {
	rd := makeRD(100, 100)
	input := append(rd, []byte{10, 0, 0, 1}...)

	got, err := UnmarshalType1(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.GetRouteTypeSpec() == nil {
		t.Error("GetRouteTypeSpec() returned nil")
	}
	if got.getRD() == nil {
		t.Error("getRD() returned nil")
	}
	if !bytes.Equal(got.getOriginatorIP(), []byte{10, 0, 0, 1}) {
		t.Error("getOriginatorIP() mismatch")
	}
	if got.getMulticastSource() != nil {
		t.Error("getMulticastSource() should be nil for Type 1")
	}
	if got.getMulticastGroup() != nil {
		t.Error("getMulticastGroup() should be nil for Type 1")
	}
	if got.getSourceAS() != 0 {
		t.Error("getSourceAS() should be 0 for Type 1")
	}
}

// --- RFC 6514 Section 4.2: Inter-AS I-PMSI A-D (Type 2) ---

func TestRFC6514_Type2_Valid(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	input := append(rd, as...)

	got, err := UnmarshalType2(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SourceAS != 65000 {
		t.Errorf("SourceAS = %d, want 65000", got.SourceAS)
	}
}

func TestRFC6514_Type2_LargeAS(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 4200000000) // 4-byte ASN
	input := append(rd, as...)

	got, err := UnmarshalType2(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SourceAS != 4200000000 {
		t.Errorf("SourceAS = %d, want 4200000000", got.SourceAS)
	}
}

func TestRFC6514_Type2_WrongLength(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"Too short (11)", make([]byte, 11)},
		{"Too long (13)", make([]byte, 13)},
		{"Empty", []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalType2(tt.input)
			if err == nil {
				t.Fatal("expected error for wrong length")
			}
		})
	}
}

func TestRFC6514_Type2_InterfaceMethods(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	input := append(rd, as...)

	got, err := UnmarshalType2(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.GetRouteTypeSpec() == nil {
		t.Error("GetRouteTypeSpec() returned nil")
	}
	if got.getRD() == nil {
		t.Error("getRD() returned nil")
	}
	if got.getOriginatorIP() != nil {
		t.Error("getOriginatorIP() should be nil for Type 2")
	}
	if got.getMulticastSource() != nil {
		t.Error("getMulticastSource() should be nil for Type 2")
	}
	if got.getMulticastGroup() != nil {
		t.Error("getMulticastGroup() should be nil for Type 2")
	}
	if got.getSourceAS() != 65000 {
		t.Errorf("getSourceAS() = %d, want 65000", got.getSourceAS())
	}
}

// --- RFC 6514 Section 4.3: S-PMSI A-D (Type 3) ---

func TestRFC6514_Type3_IPv4(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 32)                         // Source length (32 bits)
	input = append(input, 192, 168, 1, 1)             // Source 192.168.1.1
	input = append(input, 32)                         // Group length (32 bits)
	input = append(input, 224, 0, 0, 1)               // Group 224.0.0.1
	input = append(input, 10, 0, 0, 1)                // Originator 10.0.0.1

	got, err := UnmarshalType3(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MulticastSourceLen != 32 {
		t.Errorf("MulticastSourceLen = %d, want 32", got.MulticastSourceLen)
	}
	if !bytes.Equal(got.MulticastSource, []byte{192, 168, 1, 1}) {
		t.Errorf("MulticastSource = %v, want [192 168 1 1]", got.MulticastSource)
	}
	if got.MulticastGroupLen != 32 {
		t.Errorf("MulticastGroupLen = %d, want 32", got.MulticastGroupLen)
	}
	if !bytes.Equal(got.MulticastGroup, []byte{224, 0, 0, 1}) {
		t.Errorf("MulticastGroup = %v, want [224 0 0 1]", got.MulticastGroup)
	}
	if !bytes.Equal(got.OriginatorIP, []byte{10, 0, 0, 1}) {
		t.Errorf("OriginatorIP = %v, want [10 0 0 1]", got.OriginatorIP)
	}
}

func TestRFC6514_Type3_IPv6(t *testing.T) {
	rd := makeRD(100, 100)
	src := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	grp := []byte{
		0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	orig := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}

	input := rd
	input = append(input, 128)    // Source length (128 bits)
	input = append(input, src...)
	input = append(input, 128)    // Group length (128 bits)
	input = append(input, grp...)
	input = append(input, orig...)

	got, err := UnmarshalType3(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MulticastSourceLen != 128 {
		t.Errorf("MulticastSourceLen = %d, want 128", got.MulticastSourceLen)
	}
	if !bytes.Equal(got.MulticastSource, src) {
		t.Error("MulticastSource mismatch")
	}
	if !bytes.Equal(got.MulticastGroup, grp) {
		t.Error("MulticastGroup mismatch")
	}
	if !bytes.Equal(got.OriginatorIP, orig) {
		t.Error("OriginatorIP mismatch")
	}
}

func TestRFC6514_Type3_ZeroLengthSourceGroup(t *testing.T) {
	// Wildcard source (*, 0 length) and wildcard group (*, 0 length)
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 0)                          // Source length 0
	input = append(input, 0)                          // Group length 0
	input = append(input, 10, 0, 0, 1)                // Originator

	got, err := UnmarshalType3(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MulticastSourceLen != 0 {
		t.Errorf("MulticastSourceLen = %d, want 0", got.MulticastSourceLen)
	}
	if len(got.MulticastSource) != 0 {
		t.Errorf("MulticastSource should be empty, got %v", got.MulticastSource)
	}
	if got.MulticastGroupLen != 0 {
		t.Errorf("MulticastGroupLen = %d, want 0", got.MulticastGroupLen)
	}
}

func TestRFC6514_Type3_TooShort(t *testing.T) {
	_, err := UnmarshalType3(make([]byte, 9))
	if err == nil {
		t.Fatal("expected error for input shorter than minimum 10 bytes")
	}
}

func TestRFC6514_Type3_TruncatedSource(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 32) // Source length 32 bits = 4 bytes
	input = append(input, 192, 168) // Only 2 bytes

	_, err := UnmarshalType3(input)
	if err == nil {
		t.Fatal("expected error for truncated source")
	}
}

func TestRFC6514_Type3_TruncatedGroup(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32) // Group length 32 bits
	input = append(input, 224, 0) // Only 2 bytes

	_, err := UnmarshalType3(input)
	if err == nil {
		t.Fatal("expected error for truncated group")
	}
}

func TestRFC6514_Type3_InvalidOriginatorIPLength(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)
	input = append(input, 10, 0, 1) // 3 bytes (invalid, not 4 or 16)

	_, err := UnmarshalType3(input)
	if err == nil {
		t.Fatal("expected error for invalid originator IP length")
	}
}

func TestRFC6514_Type3_MissingGroupLength(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 0) // Source length 0
	// Missing group length byte

	_, err := UnmarshalType3(input)
	if err == nil {
		t.Fatal("expected error for missing group length")
	}
}

func TestRFC6514_Type3_InterfaceMethods(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)
	input = append(input, 10, 0, 0, 1)

	got, err := UnmarshalType3(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.GetRouteTypeSpec() == nil {
		t.Error("GetRouteTypeSpec() returned nil")
	}
	if got.getRD() == nil {
		t.Error("getRD() returned nil")
	}
	if !bytes.Equal(got.getOriginatorIP(), []byte{10, 0, 0, 1}) {
		t.Error("getOriginatorIP() mismatch")
	}
	if !bytes.Equal(got.getMulticastSource(), []byte{192, 168, 1, 1}) {
		t.Error("getMulticastSource() mismatch")
	}
	if !bytes.Equal(got.getMulticastGroup(), []byte{224, 0, 0, 1}) {
		t.Error("getMulticastGroup() mismatch")
	}
	if got.getSourceAS() != 0 {
		t.Error("getSourceAS() should be 0 for Type 3")
	}
}

// --- RFC 6514 Section 4.4: Leaf A-D (Type 4) ---

func TestRFC6514_Type4_IPv4RouteKey(t *testing.T) {
	// Route key = Type 3 NLRI data (without type/length): RD + src_len + src + grp_len + grp + orig
	rd := makeRD(100, 100)
	routeKey := rd
	routeKey = append(routeKey, 32)
	routeKey = append(routeKey, 192, 168, 1, 1)
	routeKey = append(routeKey, 32)
	routeKey = append(routeKey, 224, 0, 0, 1)
	routeKey = append(routeKey, 10, 0, 0, 1)

	origIP := []byte{10, 0, 0, 2}
	input := append(routeKey, origIP...)

	got, err := UnmarshalType4(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got.RouteKey, routeKey) {
		t.Error("RouteKey mismatch")
	}
	if !bytes.Equal(got.OriginatorIP, origIP) {
		t.Error("OriginatorIP mismatch")
	}
}

func TestRFC6514_Type4_TooShort(t *testing.T) {
	_, err := UnmarshalType4(make([]byte, 3))
	if err == nil {
		t.Fatal("expected error for input shorter than 4 bytes")
	}
}

func TestRFC6514_Type4_RouteKeyTooShort(t *testing.T) {
	// 4 bytes total: route key = 0 bytes (< 8 required), originator = 4 bytes
	_, err := UnmarshalType4([]byte{10, 0, 0, 1})
	if err != nil {
		// Route key length < 8, but implementation tries IPv4 first:
		// routeKeyLen = 4-4 = 0, which is < 8, so it tries IPv6
		// len(b) = 4 < 16, so IPv6 fails too -> error
		if !strings.Contains(err.Error(), "invalid Type4 format") {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

func TestRFC6514_Type4_InterfaceMethods(t *testing.T) {
	rd := makeRD(100, 100)
	routeKey := rd
	routeKey = append(routeKey, 32)
	routeKey = append(routeKey, 192, 168, 1, 1)
	routeKey = append(routeKey, 32)
	routeKey = append(routeKey, 224, 0, 0, 1)
	routeKey = append(routeKey, 10, 0, 0, 1)
	input := append(routeKey, 10, 0, 0, 2)

	got, err := UnmarshalType4(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.GetRouteTypeSpec() == nil {
		t.Error("GetRouteTypeSpec() returned nil")
	}
	// Type 4 RD is embedded in route key, getRD() returns nil
	if got.getRD() != nil {
		t.Error("getRD() should be nil for Type 4")
	}
	if !bytes.Equal(got.getOriginatorIP(), []byte{10, 0, 0, 2}) {
		t.Error("getOriginatorIP() mismatch")
	}
	if got.getMulticastSource() != nil {
		t.Error("getMulticastSource() should be nil for Type 4")
	}
	if got.getMulticastGroup() != nil {
		t.Error("getMulticastGroup() should be nil for Type 4")
	}
	if got.getSourceAS() != 0 {
		t.Error("getSourceAS() should be 0 for Type 4")
	}
}

// --- RFC 6514 Section 4.5: Source Active A-D (Type 5) ---

func TestRFC6514_Type5_IPv4(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)

	got, err := UnmarshalType5(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MulticastSourceLen != 32 {
		t.Errorf("MulticastSourceLen = %d, want 32", got.MulticastSourceLen)
	}
	if !bytes.Equal(got.MulticastSource, []byte{192, 168, 1, 1}) {
		t.Errorf("MulticastSource mismatch")
	}
	if !bytes.Equal(got.MulticastGroup, []byte{224, 0, 0, 1}) {
		t.Errorf("MulticastGroup mismatch")
	}
}

func TestRFC6514_Type5_IPv6(t *testing.T) {
	rd := makeRD(100, 100)
	src := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	grp := []byte{
		0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	input := rd
	input = append(input, 128)
	input = append(input, src...)
	input = append(input, 128)
	input = append(input, grp...)

	got, err := UnmarshalType5(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got.MulticastSource, src) {
		t.Error("MulticastSource mismatch")
	}
	if !bytes.Equal(got.MulticastGroup, grp) {
		t.Error("MulticastGroup mismatch")
	}
}

func TestRFC6514_Type5_ZeroLengthSource(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 0) // Source length 0 (wildcard)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)

	got, err := UnmarshalType5(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MulticastSourceLen != 0 {
		t.Errorf("MulticastSourceLen = %d, want 0", got.MulticastSourceLen)
	}
}

func TestRFC6514_Type5_TooShort(t *testing.T) {
	_, err := UnmarshalType5(make([]byte, 9))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestRFC6514_Type5_TrailingBytes(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)
	input = append(input, 0xFF) // Extra trailing byte

	_, err := UnmarshalType5(input)
	if err == nil {
		t.Fatal("expected error for trailing bytes")
	}
	if !strings.Contains(err.Error(), "trailing bytes") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRFC6514_Type5_TruncatedSource(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 32)     // 32 bits = 4 bytes needed
	input = append(input, 192)    // Only 1 byte

	_, err := UnmarshalType5(input)
	if err == nil {
		t.Fatal("expected error for truncated source")
	}
}

func TestRFC6514_Type5_InterfaceMethods(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)

	got, err := UnmarshalType5(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.GetRouteTypeSpec() == nil {
		t.Error("GetRouteTypeSpec() returned nil")
	}
	if got.getRD() == nil {
		t.Error("getRD() returned nil")
	}
	if got.getOriginatorIP() != nil {
		t.Error("getOriginatorIP() should be nil for Type 5")
	}
	if got.getMulticastSource() == nil {
		t.Error("getMulticastSource() should not be nil")
	}
	if got.getMulticastGroup() == nil {
		t.Error("getMulticastGroup() should not be nil")
	}
	if got.getSourceAS() != 0 {
		t.Error("getSourceAS() should be 0 for Type 5")
	}
}

// --- RFC 6514 Section 4.6: Shared Tree Join (Type 6) ---

func TestRFC6514_Type6_IPv4(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	input := rd
	input = append(input, as...)
	input = append(input, 32)
	input = append(input, 0, 0, 0, 0)    // C-RP wildcard
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)

	got, err := UnmarshalType6(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SourceAS != 65000 {
		t.Errorf("SourceAS = %d, want 65000", got.SourceAS)
	}
	if !bytes.Equal(got.MulticastSource, []byte{0, 0, 0, 0}) {
		t.Error("MulticastSource (C-RP) mismatch")
	}
	if !bytes.Equal(got.MulticastGroup, []byte{224, 0, 0, 1}) {
		t.Error("MulticastGroup mismatch")
	}
}

func TestRFC6514_Type6_IPv6(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	src := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	grp := []byte{
		0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	input := rd
	input = append(input, as...)
	input = append(input, 128)
	input = append(input, src...)
	input = append(input, 128)
	input = append(input, grp...)

	got, err := UnmarshalType6(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got.MulticastSource, src) {
		t.Error("MulticastSource mismatch")
	}
	if !bytes.Equal(got.MulticastGroup, grp) {
		t.Error("MulticastGroup mismatch")
	}
}

func TestRFC6514_Type6_TooShort(t *testing.T) {
	_, err := UnmarshalType6(make([]byte, 13))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestRFC6514_Type6_TrailingBytes(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	input := rd
	input = append(input, as...)
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)
	input = append(input, 0xFF) // Extra byte

	_, err := UnmarshalType6(input)
	if err == nil {
		t.Fatal("expected error for trailing bytes")
	}
}

func TestRFC6514_Type6_MissingGroupLengthByte(t *testing.T) {
	// RD(8) + AS(4) + src_len(1) + src(0) = 13 bytes -> fails minimum 14
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	input := append(rd, as...)
	input = append(input, 0) // src_len = 0, no group length byte

	_, err := UnmarshalType6(input)
	if err == nil {
		t.Fatal("expected error for missing group length byte")
	}
}

func TestRFC6514_Type6_InterfaceMethods(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	input := rd
	input = append(input, as...)
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)

	got, err := UnmarshalType6(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.GetRouteTypeSpec() == nil {
		t.Error("GetRouteTypeSpec() returned nil")
	}
	if got.getRD() == nil {
		t.Error("getRD() returned nil")
	}
	if got.getOriginatorIP() != nil {
		t.Error("getOriginatorIP() should be nil for Type 6")
	}
	if got.getMulticastSource() == nil {
		t.Error("getMulticastSource() should not be nil")
	}
	if got.getMulticastGroup() == nil {
		t.Error("getMulticastGroup() should not be nil")
	}
	if got.getSourceAS() != 65000 {
		t.Errorf("getSourceAS() = %d, want 65000", got.getSourceAS())
	}
}

// --- RFC 6514 Section 4.7: Source Tree Join (Type 7) ---

func TestRFC6514_Type7_IPv4(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	input := rd
	input = append(input, as...)
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1) // C-S source
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)

	got, err := UnmarshalType7(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SourceAS != 65000 {
		t.Errorf("SourceAS = %d, want 65000", got.SourceAS)
	}
	if !bytes.Equal(got.MulticastSource, []byte{192, 168, 1, 1}) {
		t.Error("MulticastSource (C-S) mismatch")
	}
	if !bytes.Equal(got.MulticastGroup, []byte{224, 0, 0, 1}) {
		t.Error("MulticastGroup mismatch")
	}
}

func TestRFC6514_Type7_IPv6(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	src := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	grp := []byte{
		0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	input := rd
	input = append(input, as...)
	input = append(input, 128)
	input = append(input, src...)
	input = append(input, 128)
	input = append(input, grp...)

	got, err := UnmarshalType7(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got.MulticastSource, src) {
		t.Error("MulticastSource mismatch")
	}
	if !bytes.Equal(got.MulticastGroup, grp) {
		t.Error("MulticastGroup mismatch")
	}
}

func TestRFC6514_Type7_TooShort(t *testing.T) {
	_, err := UnmarshalType7(make([]byte, 13))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestRFC6514_Type7_TrailingBytes(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	input := rd
	input = append(input, as...)
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)
	input = append(input, 0xFF)

	_, err := UnmarshalType7(input)
	if err == nil {
		t.Fatal("expected error for trailing bytes")
	}
}

func TestRFC6514_Type7_InterfaceMethods(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	input := rd
	input = append(input, as...)
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)

	got, err := UnmarshalType7(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.GetRouteTypeSpec() == nil {
		t.Error("GetRouteTypeSpec() returned nil")
	}
	if got.getRD() == nil {
		t.Error("getRD() returned nil")
	}
	if got.getOriginatorIP() != nil {
		t.Error("getOriginatorIP() should be nil for Type 7")
	}
	if got.getMulticastSource() == nil {
		t.Error("getMulticastSource() should not be nil")
	}
	if got.getMulticastGroup() == nil {
		t.Error("getMulticastGroup() should not be nil")
	}
	if got.getSourceAS() != 65000 {
		t.Errorf("getSourceAS() = %d, want 65000", got.getSourceAS())
	}
}

// --- RFC 6514: NLRI Dispatcher Tests ---

func TestRFC6514_Dispatcher_AllRouteTypes(t *testing.T) {
	rd := makeRD(100, 100)

	// Build Type 1 NLRI
	t1data := append(rd, 10, 0, 0, 1)
	t1nlri := []byte{0x01, byte(len(t1data))}
	t1nlri = append(t1nlri, t1data...)

	// Build Type 2 NLRI
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)
	t2data := append(rd, as...)
	t2nlri := []byte{0x02, byte(len(t2data))}
	t2nlri = append(t2nlri, t2data...)

	// Build Type 5 NLRI
	t5data := rd
	t5data = append(t5data, 32)
	t5data = append(t5data, 192, 168, 1, 1)
	t5data = append(t5data, 32)
	t5data = append(t5data, 224, 0, 0, 1)
	t5nlri := []byte{0x05, byte(len(t5data))}
	t5nlri = append(t5nlri, t5data...)

	input := t1nlri
	input = append(input, t2nlri...)
	input = append(input, t5nlri...)

	route, err := UnmarshalMCASTVPNNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(route.Route) != 3 {
		t.Fatalf("expected 3 NLRIs, got %d", len(route.Route))
	}
	if route.Route[0].RouteType != 1 {
		t.Errorf("first NLRI type = %d, want 1", route.Route[0].RouteType)
	}
	if route.Route[1].RouteType != 2 {
		t.Errorf("second NLRI type = %d, want 2", route.Route[1].RouteType)
	}
	if route.Route[2].RouteType != 5 {
		t.Errorf("third NLRI type = %d, want 5", route.Route[2].RouteType)
	}
}

func TestRFC6514_Dispatcher_UnknownRouteType(t *testing.T) {
	input := []byte{
		0x08, 0x04, // Route Type 8 (undefined), length 4
		0x00, 0x00, 0x00, 0x00,
	}
	_, err := UnmarshalMCASTVPNNLRI(input)
	if err == nil {
		t.Fatal("expected error for unknown route type")
	}
	if !strings.Contains(err.Error(), "unknown MCAST-VPN route type 8") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRFC6514_Dispatcher_EmptyInput(t *testing.T) {
	_, err := UnmarshalMCASTVPNNLRI([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestRFC6514_Dispatcher_TruncatedHeader(t *testing.T) {
	_, err := UnmarshalMCASTVPNNLRI([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestRFC6514_Dispatcher_LengthExceedsData(t *testing.T) {
	input := []byte{
		0x01, 0x0c, // Type 1, length 12
		0x00, 0x00, 0x00, 0x64, // Only 4 bytes instead of 12
	}
	_, err := UnmarshalMCASTVPNNLRI(input)
	if err == nil {
		t.Fatal("expected error for length exceeding data")
	}
}

func TestRFC6514_Dispatcher_RouteTypeZero(t *testing.T) {
	input := []byte{
		0x00, 0x04, // Route Type 0 (invalid)
		0x00, 0x00, 0x00, 0x00,
	}
	_, err := UnmarshalMCASTVPNNLRI(input)
	if err == nil {
		t.Fatal("expected error for route type 0")
	}
}

// --- RFC 6514: NLRI Accessor Method Tests ---

func TestRFC6514_NLRIAccessors(t *testing.T) {
	rd := makeRD(100, 100)

	// Type 1 NLRI
	t1data := append(rd, 10, 0, 0, 1)
	t1nlri := []byte{0x01, byte(len(t1data))}
	t1nlri = append(t1nlri, t1data...)

	route, err := UnmarshalMCASTVPNNLRI(t1nlri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	n := route.Route[0]
	if n.GetMCASTVPNRouteType() != 1 {
		t.Errorf("GetMCASTVPNRouteType() = %d, want 1", n.GetMCASTVPNRouteType())
	}
	if n.GetMCASTVPNRD() == nil {
		t.Error("GetMCASTVPNRD() returned nil")
	}
	if !bytes.Equal(n.GetMCASTVPNOriginatorIP(), []byte{10, 0, 0, 1}) {
		t.Error("GetMCASTVPNOriginatorIP() mismatch")
	}
	if n.GetMCASTVPNMulticastSource() != nil {
		t.Error("GetMCASTVPNMulticastSource() should be nil for Type 1")
	}
	if n.GetMCASTVPNMulticastGroup() != nil {
		t.Error("GetMCASTVPNMulticastGroup() should be nil for Type 1")
	}
	if n.GetMCASTVPNSourceAS() != 0 {
		t.Error("GetMCASTVPNSourceAS() should be 0 for Type 1")
	}
}

func TestRFC6514_NLRIAccessors_Type6WithSourceAS(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)

	t6data := rd
	t6data = append(t6data, as...)
	t6data = append(t6data, 32)
	t6data = append(t6data, 192, 168, 1, 1)
	t6data = append(t6data, 32)
	t6data = append(t6data, 224, 0, 0, 1)
	t6nlri := []byte{0x06, byte(len(t6data))}
	t6nlri = append(t6nlri, t6data...)

	route, err := UnmarshalMCASTVPNNLRI(t6nlri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	n := route.Route[0]
	if n.GetMCASTVPNRouteType() != 6 {
		t.Errorf("GetMCASTVPNRouteType() = %d, want 6", n.GetMCASTVPNRouteType())
	}
	if n.GetMCASTVPNSourceAS() != 65000 {
		t.Errorf("GetMCASTVPNSourceAS() = %d, want 65000", n.GetMCASTVPNSourceAS())
	}
	if !bytes.Equal(n.GetMCASTVPNMulticastSource(), []byte{192, 168, 1, 1}) {
		t.Error("GetMCASTVPNMulticastSource() mismatch")
	}
	if !bytes.Equal(n.GetMCASTVPNMulticastGroup(), []byte{224, 0, 0, 1}) {
		t.Error("GetMCASTVPNMulticastGroup() mismatch")
	}
}

// --- RFC 6514: Non-Byte-Aligned Prefix Length Tests ---

func TestRFC6514_Type3_NonByteAlignedPrefixLength(t *testing.T) {
	// Source with /24 prefix (24 bits = 3 bytes)
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 24)             // 24-bit source
	input = append(input, 192, 168, 1)    // 3 bytes
	input = append(input, 32)             // 32-bit group
	input = append(input, 224, 0, 0, 1)
	input = append(input, 10, 0, 0, 1)    // Originator IPv4

	got, err := UnmarshalType3(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MulticastSourceLen != 24 {
		t.Errorf("MulticastSourceLen = %d, want 24", got.MulticastSourceLen)
	}
	if len(got.MulticastSource) != 3 {
		t.Errorf("MulticastSource length = %d, want 3", len(got.MulticastSource))
	}
}

func TestRFC6514_Type5_NonByteAlignedPrefixLength(t *testing.T) {
	// Source with 25-bit prefix: (25+7)/8 = 4 bytes
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 25)
	input = append(input, 192, 168, 1, 0) // 4 bytes for /25
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)

	got, err := UnmarshalType5(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MulticastSourceLen != 25 {
		t.Errorf("MulticastSourceLen = %d, want 25", got.MulticastSourceLen)
	}
	// (25+7)/8 = 4 bytes
	if len(got.MulticastSource) != 4 {
		t.Errorf("MulticastSource length = %d, want 4", len(got.MulticastSource))
	}
}

// --- RFC 6514: RD Type Variations ---

func TestRFC6514_Type2_AllRDTypes(t *testing.T) {
	tests := []struct {
		name string
		rd   []byte
	}{
		{"RD Type 0", makeRD(100, 200)},
		{"RD Type 1", makeRDType1([4]byte{10, 0, 0, 1}, 100)},
		{"RD Type 2", makeRDType2(65000, 100)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := make([]byte, 4)
			binary.BigEndian.PutUint32(as, 65000)
			input := append(tt.rd, as...)

			got, err := UnmarshalType2(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.RD == nil {
				t.Fatal("RD is nil")
			}
			if got.SourceAS != 65000 {
				t.Errorf("SourceAS = %d, want 65000", got.SourceAS)
			}
		})
	}
}

func TestRFC6514_Type5_AllRDTypes(t *testing.T) {
	tests := []struct {
		name string
		rd   []byte
	}{
		{"RD Type 0", makeRD(100, 200)},
		{"RD Type 1", makeRDType1([4]byte{10, 0, 0, 1}, 100)},
		{"RD Type 2", makeRDType2(65000, 100)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.rd
			input = append(input, 32)
			input = append(input, 192, 168, 1, 1)
			input = append(input, 32)
			input = append(input, 224, 0, 0, 1)

			got, err := UnmarshalType5(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.RD == nil {
				t.Fatal("RD is nil")
			}
		})
	}
}

// --- RFC 6514: Invalid RD in Various Types ---

func TestRFC6514_Type3_InvalidRD(t *testing.T) {
	rd := make([]byte, 8)
	binary.BigEndian.PutUint16(rd[0:2], 5) // Invalid RD type
	input := rd
	input = append(input, 0, 0)
	input = append(input, 10, 0, 0, 1)

	_, err := UnmarshalType3(input)
	if err == nil {
		t.Fatal("expected error for invalid RD type")
	}
}

func TestRFC6514_Type5_InvalidRD(t *testing.T) {
	rd := make([]byte, 8)
	binary.BigEndian.PutUint16(rd[0:2], 5)
	input := rd
	input = append(input, 0, 0)

	_, err := UnmarshalType5(input)
	if err == nil {
		t.Fatal("expected error for invalid RD type")
	}
}

func TestRFC6514_Type6_InvalidRD(t *testing.T) {
	rd := make([]byte, 8)
	binary.BigEndian.PutUint16(rd[0:2], 5)
	as := make([]byte, 4)
	input := rd
	input = append(input, as...)
	input = append(input, 0, 0)

	_, err := UnmarshalType6(input)
	if err == nil {
		t.Fatal("expected error for invalid RD type")
	}
}

func TestRFC6514_Type7_InvalidRD(t *testing.T) {
	rd := make([]byte, 8)
	binary.BigEndian.PutUint16(rd[0:2], 5)
	as := make([]byte, 4)
	input := rd
	input = append(input, as...)
	input = append(input, 0, 0)

	_, err := UnmarshalType7(input)
	if err == nil {
		t.Fatal("expected error for invalid RD type")
	}
}

// --- RFC 6514: Boundary Value Tests ---

func TestRFC6514_Type2_ZeroAS(t *testing.T) {
	rd := makeRD(100, 100)
	input := append(rd, 0, 0, 0, 0) // AS = 0

	got, err := UnmarshalType2(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SourceAS != 0 {
		t.Errorf("SourceAS = %d, want 0", got.SourceAS)
	}
}

func TestRFC6514_Type2_MaxAS(t *testing.T) {
	rd := makeRD(100, 100)
	input := append(rd, 0xFF, 0xFF, 0xFF, 0xFF) // AS = max uint32

	got, err := UnmarshalType2(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SourceAS != 0xFFFFFFFF {
		t.Errorf("SourceAS = %d, want %d", got.SourceAS, uint32(0xFFFFFFFF))
	}
}

func TestRFC6514_Type6_ZeroAS(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 0, 0, 0, 0) // AS = 0
	input = append(input, 32)
	input = append(input, 0, 0, 0, 0)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)

	got, err := UnmarshalType6(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SourceAS != 0 {
		t.Errorf("SourceAS = %d, want 0", got.SourceAS)
	}
}

// --- RFC 6514: Verify Data Isolation (Copy Semantics) ---

func TestRFC6514_Type1_DataIsolation(t *testing.T) {
	rd := makeRD(100, 100)
	origIP := []byte{10, 0, 0, 1}
	input := append(rd, origIP...)
	inputCopy := make([]byte, len(input))
	copy(inputCopy, input)

	got, err := UnmarshalType1(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate original input
	input[8] = 0xFF

	// Parsed data should be unaffected
	if got.OriginatorIP[0] == 0xFF {
		t.Error("OriginatorIP shares memory with input slice")
	}
}

func TestRFC6514_Type3_DataIsolation(t *testing.T) {
	rd := makeRD(100, 100)
	input := rd
	input = append(input, 32)
	input = append(input, 192, 168, 1, 1)
	input = append(input, 32)
	input = append(input, 224, 0, 0, 1)
	input = append(input, 10, 0, 0, 1)

	got, err := UnmarshalType3(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate source bytes in original input (offset: 8 RD + 1 len = 9)
	input[9] = 0xFF

	if got.MulticastSource[0] == 0xFF {
		t.Error("MulticastSource shares memory with input slice")
	}
}

// --- RFC 6514: RouteTypeSpec Interface Compliance ---

func TestRFC6514_InterfaceCompliance(t *testing.T) {
	rd := makeRD(100, 100)

	// Verify all 7 types implement RouteTypeSpec
	implementations := []struct {
		name    string
		builder func() (RouteTypeSpec, error)
	}{
		{"Type1", func() (RouteTypeSpec, error) {
			return UnmarshalType1(append(rd, 10, 0, 0, 1))
		}},
		{"Type2", func() (RouteTypeSpec, error) {
			return UnmarshalType2(append(rd, 0, 0, 0xFD, 0xE8))
		}},
		{"Type3", func() (RouteTypeSpec, error) {
			data := rd
			data = append(data, 32)
			data = append(data, 192, 168, 1, 1)
			data = append(data, 32)
			data = append(data, 224, 0, 0, 1)
			data = append(data, 10, 0, 0, 1)
			return UnmarshalType3(data)
		}},
		{"Type4", func() (RouteTypeSpec, error) {
			data := rd
			data = append(data, 32)
			data = append(data, 192, 168, 1, 1)
			data = append(data, 32)
			data = append(data, 224, 0, 0, 1)
			data = append(data, 10, 0, 0, 1)
			data = append(data, 10, 0, 0, 2)
			return UnmarshalType4(data)
		}},
		{"Type5", func() (RouteTypeSpec, error) {
			data := rd
			data = append(data, 32)
			data = append(data, 192, 168, 1, 1)
			data = append(data, 32)
			data = append(data, 224, 0, 0, 1)
			return UnmarshalType5(data)
		}},
		{"Type6", func() (RouteTypeSpec, error) {
			as := make([]byte, 4)
			binary.BigEndian.PutUint32(as, 65000)
			data := append(rd, as...)
			data = append(data, 32)
			data = append(data, 192, 168, 1, 1)
			data = append(data, 32)
			data = append(data, 224, 0, 0, 1)
			return UnmarshalType6(data)
		}},
		{"Type7", func() (RouteTypeSpec, error) {
			as := make([]byte, 4)
			binary.BigEndian.PutUint32(as, 65000)
			data := append(rd, as...)
			data = append(data, 32)
			data = append(data, 192, 168, 1, 1)
			data = append(data, 32)
			data = append(data, 224, 0, 0, 1)
			return UnmarshalType7(data)
		}},
	}

	for _, impl := range implementations {
		t.Run(impl.name, func(t *testing.T) {
			spec, err := impl.builder()
			if err != nil {
				t.Fatalf("failed to build %s: %v", impl.name, err)
			}
			// Verify interface methods exist and don't panic
			_ = spec.GetRouteTypeSpec()
			_ = spec.getRD()
			_ = spec.getOriginatorIP()
			_ = spec.getMulticastSource()
			_ = spec.getMulticastGroup()
			_ = spec.getSourceAS()
		})
	}
}

// --- RFC 6514: Missing Source/Group Length Byte Tests ---

func TestRFC6514_Type3_MissingSourceLength(t *testing.T) {
	_, err := UnmarshalType3(make([]byte, 9))
	if err == nil {
		t.Fatal("expected error for 9-byte input")
	}
}

func TestRFC6514_Type6_MissingSourceLength(t *testing.T) {
	// RD(8) + AS(4) = 12 bytes, missing source length
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	input := append(rd, as...)
	// Need 14 bytes minimum to pass initial check
	input = append(input, 0, 0)

	// This passes minimum check (14 bytes) but source length byte at position 12
	// says 0, group length at position 13 says 0 -> consumed 14 == len(b) 14 -> passes
	got, err := UnmarshalType6(input)
	if err != nil {
		// Both source and group are 0 length, and consumed == total -> valid
		t.Fatalf("unexpected error: %v", err)
	}
	if got.MulticastSourceLen != 0 {
		t.Errorf("expected 0 source len, got %d", got.MulticastSourceLen)
	}
}

// --- RFC 6514: Realistic Multi-NLRI Scenarios ---

func TestRFC6514_MultiNLRI_AllSevenTypes(t *testing.T) {
	rd := makeRD(100, 100)
	as := make([]byte, 4)
	binary.BigEndian.PutUint32(as, 65000)

	buildNLRI := func(routeType byte, data []byte) []byte {
		return append([]byte{routeType, byte(len(data))}, data...)
	}

	// Type 1: RD + IPv4
	t1 := buildNLRI(1, append(rd, 10, 0, 0, 1))

	// Type 2: RD + AS
	t2 := buildNLRI(2, append(rd, as...))

	// Type 3: RD + src + grp + orig
	t3data := rd
	t3data = append(t3data, 32, 192, 168, 1, 1)
	t3data = append(t3data, 32, 224, 0, 0, 1)
	t3data = append(t3data, 10, 0, 0, 1)
	t3 := buildNLRI(3, t3data)

	// Type 4: route key (>= 8 bytes) + orig IPv4
	t4key := rd
	t4key = append(t4key, 32, 192, 168, 1, 1)
	t4key = append(t4key, 32, 224, 0, 0, 1)
	t4key = append(t4key, 10, 0, 0, 1)
	t4data := append(t4key, 10, 0, 0, 2)
	t4 := buildNLRI(4, t4data)

	// Type 5: RD + src + grp
	t5data := rd
	t5data = append(t5data, 32, 192, 168, 1, 1)
	t5data = append(t5data, 32, 224, 0, 0, 1)
	t5 := buildNLRI(5, t5data)

	// Type 6: RD + AS + src + grp
	t6data := append(rd, as...)
	t6data = append(t6data, 32, 192, 168, 1, 1)
	t6data = append(t6data, 32, 224, 0, 0, 1)
	t6 := buildNLRI(6, t6data)

	// Type 7: RD + AS + src + grp
	t7data := append(rd, as...)
	t7data = append(t7data, 32, 192, 168, 1, 1)
	t7data = append(t7data, 32, 224, 0, 0, 1)
	t7 := buildNLRI(7, t7data)

	// Concatenate all
	input := t1
	input = append(input, t2...)
	input = append(input, t3...)
	input = append(input, t4...)
	input = append(input, t5...)
	input = append(input, t6...)
	input = append(input, t7...)

	route, err := UnmarshalMCASTVPNNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(route.Route) != 7 {
		t.Fatalf("expected 7 NLRIs, got %d", len(route.Route))
	}
	for i, n := range route.Route {
		expectedType := uint8(i + 1)
		if n.RouteType != expectedType {
			t.Errorf("NLRI[%d] type = %d, want %d", i, n.RouteType, expectedType)
		}
	}
}

func TestRFC6514_Dispatcher_ErrorInMiddleNLRI(t *testing.T) {
	rd := makeRD(100, 100)

	// Valid Type 1
	t1data := append(rd, 10, 0, 0, 1)
	t1 := append([]byte{0x01, byte(len(t1data))}, t1data...)

	// Invalid Type 1 (bad originator IP length: 3 bytes)
	badRD := makeRD(100, 100)
	badData := append(badRD, 10, 0, 1) // 3-byte IP
	bad := append([]byte{0x01, byte(len(badData))}, badData...)

	input := append(t1, bad...)
	_, err := UnmarshalMCASTVPNNLRI(input)
	if err == nil {
		t.Fatal("expected error when second NLRI fails to parse")
	}
}

// --- RFC 6514: Verify RD String() Representation ---

func TestRFC6514_RDStringRepresentation(t *testing.T) {
	tests := []struct {
		name string
		rd   []byte
	}{
		{"RD Type 0", makeRD(100, 200)},
		{"RD Type 1", makeRDType1([4]byte{10, 0, 0, 1}, 100)},
		{"RD Type 2", makeRDType2(65000, 100)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd, err := base.MakeRD(tt.rd)
			if err != nil {
				t.Fatalf("MakeRD failed: %v", err)
			}
			s := rd.String()
			if s == "" {
				t.Error("RD.String() returned empty string")
			}
		})
	}
}
