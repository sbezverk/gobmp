package bgp

import (
	"strings"
	"testing"
)

func TestTypeN_ShortValue(t *testing.T) {
	tests := []struct {
		name string
		fn   func(uint8, []byte) string
		want string
	}{
		{"type0 short", func(st uint8, v []byte) string { return type0(st, v) }, "invalid-type0"},
		{"type1 short", func(st uint8, v []byte) string { return type1(st, v) }, "invalid-type1"},
		{"type2 short", func(st uint8, v []byte) string { return type2(st, v) }, "invalid-type2"},
		{"type3 short", func(st uint8, v []byte) string { return type3(st, v) }, "invalid-type3"},
		{"type6 short", func(st uint8, v []byte) string { return type6(st, v) }, "invalid-type6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fn(0x02, []byte{0x01, 0x02})
			if !strings.HasPrefix(got, tt.want) {
				t.Errorf("got %q, want prefix %q", got, tt.want)
			}
		})
	}
}

func TestTypeN_ValidValue(t *testing.T) {
	// type0: 2-byte AS + 4-byte value
	got := type0(0x02, []byte{0x00, 0x64, 0x00, 0x00, 0x00, 0x01})
	if !strings.Contains(got, "100:1") {
		t.Errorf("type0 got %q, want contains '100:1'", got)
	}
	// type3: opaque color
	got = type3(0x0b, []byte{0x00, 0x00, 0x00, 0x0A})
	if !strings.Contains(got, "10") {
		t.Errorf("type3 got %q, want contains '10'", got)
	}
}

func TestMakeExtCommunity_OpaqueType(t *testing.T) {
	// Type 0x03 (opaque), SubType 0x0b (Color), value bytes
	raw := []byte{0x03, 0x0b, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00}
	ec, err := makeExtCommunity(raw)
	if err != nil {
		t.Fatalf("makeExtCommunity() error: %v", err)
	}
	if ec.SubType == nil || *ec.SubType != 0x0b {
		t.Errorf("SubType = %v, want 0x0b", ec.SubType)
	}
	// After fix: p starts at 1, SubType read at b[1], p++ -> p=2
	// Value = b[2:] = 6 bytes: [0x00, 0x00, 0x00, 0x0A, 0x00, 0x00]
	if len(ec.Value) != 6 {
		t.Fatalf("Value length = %d, want 6", len(ec.Value))
	}
	if ec.Value[3] != 0x0A {
		t.Errorf("Value[3] = 0x%02x, want 0x0A", ec.Value[3])
	}
}

func TestAddPathCapability_MultipleTLVs(t *testing.T) {
	o := &OpenMessage{
		Capabilities: Capability{
			69: []*CapabilityData{
				{Value: []byte{0x00, 0x01, 0x01, 0x03}}, // AFI=1 SAFI=1 Send/Receive
				{Value: []byte{0x00, 0x02, 0x01, 0x03}}, // AFI=2 SAFI=1 Send/Receive
			},
		},
	}
	m := o.AddPathCapability()
	ipv4Key := NLRIMessageType(1, 1)
	ipv6Key := NLRIMessageType(2, 1)
	if !m[ipv4Key] {
		t.Errorf("IPv4 Unicast AddPath not set")
	}
	if !m[ipv6Key] {
		t.Errorf("IPv6 Unicast AddPath not set")
	}
}

func TestAddPathCapability_InvalidLength(t *testing.T) {
	o := &OpenMessage{
		Capabilities: Capability{
			69: []*CapabilityData{
				{Value: []byte{0x00, 0x01, 0x01}},       // 3 bytes, not multiple of 4
				{Value: []byte{0x00, 0x02, 0x01, 0x03}}, // valid
			},
		},
	}
	m := o.AddPathCapability()
	ipv6Key := NLRIMessageType(2, 1)
	if !m[ipv6Key] {
		t.Errorf("IPv6 Unicast AddPath not set after skipping invalid TLV")
	}
}

func TestUnmarshalAttrAS4Path_Truncated(t *testing.T) {
	// Segment type=2 (AS_SEQUENCE), length=2 ASes, but only 4 bytes of AS data (need 8)
	b := []byte{0x02, 0x02, 0x00, 0x00, 0xFD, 0xE8}
	path := unmarshalAttrAS4Path(b)
	// Truncated segment is rejected entirely, no ASes appended
	if len(path) != 0 {
		t.Errorf("got %d ASes, want 0 (truncated segment skipped entirely)", len(path))
	}
}

func TestUnmarshalAttrAS4Path_Valid(t *testing.T) {
	// Segment type=2 (AS_SEQUENCE), length=2, AS 65000 + AS 65001
	b := []byte{0x02, 0x02, 0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0xFD, 0xE9}
	path := unmarshalAttrAS4Path(b)
	if len(path) != 2 {
		t.Fatalf("got %d ASes, want 2", len(path))
	}
	if path[0] != 65000 || path[1] != 65001 {
		t.Errorf("got %v, want [65000, 65001]", path)
	}
}

func TestUnmarshalAttrAS4Path_TruncatedHeader(t *testing.T) {
	// Only 1 byte — not enough for segment header
	path := unmarshalAttrAS4Path([]byte{0x02})
	if len(path) != 0 {
		t.Errorf("got %d ASes, want 0", len(path))
	}
}
