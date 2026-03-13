package flowspec

import (
	"encoding/json"
	"testing"
)

// TestRFC8956_IPv6DestinationPrefix validates Type 1 IPv6 Destination Prefix parsing.
// RFC 8956 §3.1: Type(1) + PrefixLength(1) + Offset(1) + Prefix(variable)
func TestRFC8956_IPv6DestinationPrefix(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		wantErr    bool
		specType   uint8
		prefixLen  uint8
		offset     uint8
		prefixBytes int
	}{
		{
			name: "Destination 2001:db8::/32 offset 0",
			input: []byte{
				0x07,                         // NLRI length: 7
				0x01,                         // Type 1: Destination Prefix
				0x20,                         // Prefix length: 32
				0x00,                         // Offset: 0
				0x20, 0x01, 0x0d, 0xb8,       // Prefix: 2001:0db8 (4 bytes = ceil(32/8))
			},
			specType:    1,
			prefixLen:   32,
			offset:      0,
			prefixBytes: 4,
		},
		{
			name: "Destination 2001:db8:1::/48 offset 0",
			input: []byte{
				0x09,                                     // NLRI length: 9
				0x01,                                     // Type 1
				0x30,                                     // Prefix length: 48
				0x00,                                     // Offset: 0
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,       // 2001:db8:1:: (6 bytes)
			},
			specType:    1,
			prefixLen:   48,
			offset:      0,
			prefixBytes: 6,
		},
		{
			name: "Destination /128 full address offset 0",
			input: []byte{
				0x13,                                                                     // NLRI length: 19
				0x01,                                                                     // Type 1
				0x80,                                                                     // Prefix length: 128
				0x00,                                                                     // Offset: 0
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,                           // Prefix (16 bytes)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			specType:    1,
			prefixLen:   128,
			offset:      0,
			prefixBytes: 16,
		},
		{
			name: "Destination 2001:db8::/32 with offset 16",
			// RFC 8956: offset=16 means skip first 16 bits, encode remaining 16 bits
			// PrefixLength=32, Offset=16, so ceil((32-16)/8) = 2 prefix bytes
			input: []byte{
				0x05,             // NLRI length: 5
				0x01,             // Type 1
				0x20,             // Prefix length: 32
				0x10,             // Offset: 16
				0x0d, 0xb8,       // Prefix: 0db8 (bits 16-31 of 2001:0db8)
			},
			specType:    1,
			prefixLen:   32,
			offset:      16,
			prefixBytes: 2,
		},
		{
			name: "Destination /64 with offset 48",
			// PrefixLength=64, Offset=48, encode 16 bits = 2 bytes
			input: []byte{
				0x05,             // NLRI length: 5
				0x01,             // Type 1
				0x40,             // Prefix length: 64
				0x30,             // Offset: 48
				0xab, 0xcd,       // Last 16 bits of the /64 prefix
			},
			specType:    1,
			prefixLen:   64,
			offset:      48,
			prefixBytes: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlris, err := UnmarshalAllIPv6FlowspecNLRI(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(nlris) != 1 {
				t.Fatalf("expected 1 NLRI, got %d", len(nlris))
			}
			if len(nlris[0].Spec) < 1 {
				t.Fatal("expected at least 1 spec")
			}
			ps, ok := nlris[0].Spec[0].(*PrefixSpec)
			if !ok {
				t.Fatal("spec[0] is not PrefixSpec")
			}
			if ps.SpecType != tt.specType {
				t.Errorf("SpecType=%d, want %d", ps.SpecType, tt.specType)
			}
			if ps.PrefixLength != tt.prefixLen {
				t.Errorf("PrefixLength=%d, want %d", ps.PrefixLength, tt.prefixLen)
			}
			if ps.Offset != tt.offset {
				t.Errorf("Offset=%d, want %d", ps.Offset, tt.offset)
			}
			if len(ps.Prefix) != tt.prefixBytes {
				t.Errorf("Prefix bytes=%d, want %d", len(ps.Prefix), tt.prefixBytes)
			}
		})
	}
}

// TestRFC8956_IPv6SourcePrefix validates Type 2 IPv6 Source Prefix parsing.
func TestRFC8956_IPv6SourcePrefix(t *testing.T) {
	// Truncated: /48 with offset=0 requires ceil((48-0)/8)=6 prefix bytes, but only 4 provided
	input := []byte{
		0x07,                         // NLRI length: 7
		0x02,                         // Type 2: Source Prefix
		0x30,                         // Prefix length: 48
		0x00,                         // Offset: 0
		0xfd, 0x00, 0x00, 0x01,       // 4 bytes instead of required 6
	}
	_, err := UnmarshalAllIPv6FlowspecNLRI(input)
	if err == nil {
		t.Error("expected error for truncated IPv6 source prefix")
	}

	// Correct encoding
	input = []byte{
		0x09,                                     // NLRI length: 9
		0x02,                                     // Type 2: Source Prefix
		0x30,                                     // Prefix length: 48
		0x00,                                     // Offset: 0
		0xfd, 0x00, 0x00, 0x00, 0x00, 0x01,       // fd00:0:1:: (6 bytes)
	}
	nlris, err := UnmarshalAllIPv6FlowspecNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nlris) != 1 || len(nlris[0].Spec) != 1 {
		t.Fatal("expected 1 NLRI with 1 spec")
	}
	ps := nlris[0].Spec[0].(*PrefixSpec)
	if ps.SpecType != 2 || ps.PrefixLength != 48 || ps.Offset != 0 {
		t.Errorf("unexpected: type=%d, len=%d, offset=%d", ps.SpecType, ps.PrefixLength, ps.Offset)
	}
}

// TestRFC8956_IPv6OperatorValueTypes validates that Types 3-12 work identically
// to IPv4 in IPv6 FlowSpec mode (RFC 8956 §3.3).
func TestRFC8956_IPv6OperatorValueTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		specType uint8
		opCount  int
	}{
		{
			name: "Type 3 - IP Protocol TCP",
			input: []byte{
				0x03,       // NLRI length: 3
				0x03,       // Type 3: Next Header (IP Protocol in IPv6 context)
				0x81, 0x06, // EOL + EQ, value=6 (TCP)
			},
			specType: 3,
			opCount:  1,
		},
		{
			name: "Type 4 - Port 443",
			input: []byte{
				0x04,             // NLRI length: 4
				0x04,             // Type 4: Port
				0x91, 0x01, 0xBB, // EOL + EQ + 2-byte value = 443
			},
			specType: 4,
			opCount:  1,
		},
		{
			name: "Type 5 - Destination Port 80 or 443",
			input: []byte{
				0x06,             // NLRI length: 6
				0x05,             // Type 5: Destination Port
				0x01, 0x50,       // EQ, value=80
				0x91, 0x01, 0xBB, // EOL + EQ + 2-byte value = 443
			},
			specType: 5,
			opCount:  2,
		},
		{
			name: "Type 9 - TCP Flags SYN",
			input: []byte{
				0x03,       // NLRI length: 3
				0x09,       // Type 9: TCP Flags
				0x81, 0x02, // EOL + match bit, value=0x02 (SYN)
			},
			specType: 9,
			opCount:  1,
		},
		{
			name: "Type 12 - Fragment IsFragment",
			input: []byte{
				0x03,       // NLRI length: 3
				0x0c,       // Type 12: Fragment
				0x81, 0x02, // EOL + match bit, value=0x02 (IsFragment)
			},
			specType: 12,
			opCount:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlris, err := UnmarshalAllIPv6FlowspecNLRI(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(nlris) != 1 || len(nlris[0].Spec) != 1 {
				t.Fatalf("expected 1 NLRI with 1 spec, got %d NLRIs", len(nlris))
			}
			gs, ok := nlris[0].Spec[0].(*GenericSpec)
			if !ok {
				t.Fatal("spec is not GenericSpec")
			}
			if gs.SpecType != tt.specType {
				t.Errorf("SpecType=%d, want %d", gs.SpecType, tt.specType)
			}
			if len(gs.OpVal) != tt.opCount {
				t.Errorf("OpVal count=%d, want %d", len(gs.OpVal), tt.opCount)
			}
		})
	}
}

// TestRFC8956_IPv6MultipleNLRIs validates parsing multiple IPv6 FlowSpec NLRIs.
func TestRFC8956_IPv6MultipleNLRIs(t *testing.T) {
	input := []byte{
		// NLRI 1: dst 2001:db8::/32, proto TCP
		0x0a,                               // NLRI length: 10
		0x01,                               // Type 1: Destination
		0x20,                               // Prefix length: 32
		0x00,                               // Offset: 0
		0x20, 0x01, 0x0d, 0xb8,             // 2001:db8::
		0x03, 0x81, 0x06,                   // Type 3: proto = TCP

		// NLRI 2: src fd00::/16, dst port 80
		0x08,                               // NLRI length: 8
		0x02,                               // Type 2: Source
		0x10,                               // Prefix length: 16
		0x00,                               // Offset: 0
		0xfd, 0x00,                         // fd00::
		0x05, 0x81, 0x50,                   // Type 5: dst port = 80
	}
	nlris, err := UnmarshalAllIPv6FlowspecNLRI(input)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(nlris) != 2 {
		t.Fatalf("expected 2 NLRIs, got %d", len(nlris))
	}
	// NLRI 1: 2 specs (dst prefix + proto)
	if len(nlris[0].Spec) != 2 {
		t.Errorf("NLRI[0]: expected 2 specs, got %d", len(nlris[0].Spec))
	}
	ps := nlris[0].Spec[0].(*PrefixSpec)
	if ps.SpecType != 1 || ps.PrefixLength != 32 || ps.Offset != 0 {
		t.Errorf("NLRI[0].dst: type=%d len=%d offset=%d", ps.SpecType, ps.PrefixLength, ps.Offset)
	}
	// NLRI 2: 2 specs (src prefix + dst port)
	if len(nlris[1].Spec) != 2 {
		t.Errorf("NLRI[1]: expected 2 specs, got %d", len(nlris[1].Spec))
	}
	ps = nlris[1].Spec[0].(*PrefixSpec)
	if ps.SpecType != 2 || ps.PrefixLength != 16 || ps.Offset != 0 {
		t.Errorf("NLRI[1].src: type=%d len=%d offset=%d", ps.SpecType, ps.PrefixLength, ps.Offset)
	}
}

// TestRFC8956_IPv6PrefixOffsetEdgeCases tests edge cases in the offset field.
func TestRFC8956_IPv6PrefixOffsetEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name: "Offset equals prefix length (0 significant bits)",
			input: []byte{
				0x03,       // NLRI length: 3
				0x01,       // Type 1
				0x20,       // Prefix length: 32
				0x20,       // Offset: 32 (same as length, 0 bits to encode)
			},
			wantErr: false, // 0 prefix bytes is valid
		},
		{
			name: "Offset exceeds prefix length",
			input: []byte{
				0x03,       // NLRI length: 3
				0x01,       // Type 1
				0x20,       // Prefix length: 32
				0x40,       // Offset: 64 (> 32, invalid)
			},
			wantErr: true,
		},
		{
			name: "Offset 0 with /0 (match all)",
			input: []byte{
				0x03,       // NLRI length: 3
				0x01,       // Type 1
				0x00,       // Prefix length: 0
				0x00,       // Offset: 0
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalAllIPv6FlowspecNLRI(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("error=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

// TestRFC8956_IPv6PrefixJSON validates JSON round-trip for IPv6 PrefixSpec with offset.
func TestRFC8956_IPv6PrefixJSON(t *testing.T) {
	input := []byte{
		0x05,             // NLRI length: 5
		0x01,             // Type 1
		0x20,             // Prefix length: 32
		0x10,             // Offset: 16
		0x0d, 0xb8,       // Prefix bytes
	}
	nlris, err := UnmarshalAllIPv6FlowspecNLRI(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	ps := nlris[0].Spec[0].(*PrefixSpec)

	// Marshal to JSON
	b, err := json.Marshal(ps)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// Verify offset field is present in JSON
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}
	if _, ok := m["prefix_offset"]; !ok {
		t.Error("prefix_offset field missing from JSON output")
	}
	if m["prefix_offset"].(float64) != 16 {
		t.Errorf("prefix_offset=%v, want 16", m["prefix_offset"])
	}

	// Unmarshal back
	var ps2 PrefixSpec
	if err := json.Unmarshal(b, &ps2); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if ps2.Offset != 16 {
		t.Errorf("round-trip offset=%d, want 16", ps2.Offset)
	}
	if ps2.PrefixLength != 32 {
		t.Errorf("round-trip prefixLen=%d, want 32", ps2.PrefixLength)
	}
}

// TestRFC8956_Section3_8_2_WireExample validates the exact wire format from RFC 8956 §3.8.2.
// Hex: 02 68 41 24 68 ac f1 34
// Type=2 (Source), Length=104, Offset=65, Pattern=5 bytes (39 bits + 1 pad bit)
func TestRFC8956_Section3_8_2_WireExample(t *testing.T) {
	// Flow spec component is 8 bytes: type(1) + length(1) + offset(1) + pattern(5)
	// NLRI length field = 8
	input := []byte{
		0x08,                                     // NLRI length: 8
		0x02,                                     // Type 2: Source Prefix
		0x68,                                     // Length: 104 bits
		0x41,                                     // Offset: 65 bits
		0x24, 0x68, 0xac, 0xf1, 0x34,             // Pattern: 5 bytes (39 significant bits + 1 pad bit)
	}
	nlris, err := UnmarshalAllIPv6FlowspecNLRI(input)
	if err != nil {
		t.Fatalf("RFC 8956 §3.8.2 example parse error: %v", err)
	}
	if len(nlris) != 1 {
		t.Fatalf("expected 1 NLRI, got %d", len(nlris))
	}
	if len(nlris[0].Spec) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(nlris[0].Spec))
	}
	ps, ok := nlris[0].Spec[0].(*PrefixSpec)
	if !ok {
		t.Fatal("spec is not PrefixSpec")
	}
	if ps.SpecType != 2 {
		t.Errorf("SpecType=%d, want 2", ps.SpecType)
	}
	if ps.PrefixLength != 104 {
		t.Errorf("PrefixLength=%d, want 104", ps.PrefixLength)
	}
	if ps.Offset != 65 {
		t.Errorf("Offset=%d, want 65", ps.Offset)
	}
	// Pattern should be ceil((104-65)/8) = ceil(39/8) = 5 bytes
	if len(ps.Prefix) != 5 {
		t.Errorf("Prefix bytes=%d, want 5 (ceil(39/8))", len(ps.Prefix))
	}
	// Verify exact pattern bytes from RFC example
	expected := []byte{0x24, 0x68, 0xac, 0xf1, 0x34}
	for i, b := range expected {
		if i < len(ps.Prefix) && ps.Prefix[i] != b {
			t.Errorf("Prefix[%d]=0x%02x, want 0x%02x", i, ps.Prefix[i], b)
		}
	}
}

// TestRFC8956_IPv4UnchangedByOffset verifies IPv4 FlowSpec parsing ignores the offset
// field (IPv4 PrefixSpec does not have offset in wire format).
func TestRFC8956_IPv4UnchangedByOffset(t *testing.T) {
	input := []byte{
		0x05,                   // NLRI length: 5
		0x01,                   // Type 1: Destination Prefix
		0x18,                   // Prefix length: 24
		0x0A, 0x00, 0x01,       // Prefix: 10.0.1.0
	}
	nlris, err := UnmarshalAllFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ps := nlris[0].Spec[0].(*PrefixSpec)
	if ps.Offset != 0 {
		t.Errorf("IPv4 PrefixSpec should have offset=0, got %d", ps.Offset)
	}
	if ps.PrefixLength != 24 {
		t.Errorf("PrefixLength=%d, want 24", ps.PrefixLength)
	}
}

// TestRFC8956_IPv6EmptyWithdraw validates empty MP_UNREACH handling for IPv6.
func TestRFC8956_IPv6EmptyWithdraw(t *testing.T) {
	nlris, err := UnmarshalAllIPv6FlowspecNLRI([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlris != nil {
		t.Errorf("expected nil for empty input, got %d NLRIs", len(nlris))
	}
}

// TestRFC8956_IPv6TruncatedPrefix tests error on truncated IPv6 prefix data.
func TestRFC8956_IPv6TruncatedPrefix(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name: "Too short for header",
			input: []byte{
				0x02,       // NLRI length: 2
				0x01, 0x20, // Type + PrefixLen but no offset byte
			},
		},
		{
			name: "Prefix bytes missing",
			input: []byte{
				0x03,       // NLRI length: 3 (but needs 4 prefix bytes for /32 offset 0)
				0x01,       // Type 1
				0x20,       // Prefix length: 32
				0x00,       // Offset: 0
				// Missing 4 prefix bytes
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalAllIPv6FlowspecNLRI(tt.input)
			if err == nil {
				t.Error("expected error for truncated data")
			}
		})
	}
}
