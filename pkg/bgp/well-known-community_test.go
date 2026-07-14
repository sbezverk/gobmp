package bgp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"
)

// packCommunities encodes a list of 32-bit community values into COMMUNITIES
// attribute wire format (RFC 1997), 4 bytes each in network byte order.
func packCommunities(comms ...uint32) []byte {
	b := make([]byte, 0, len(comms)*4)
	for _, c := range comms {
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], c)
		b = append(b, tmp[:]...)
	}

	return b
}

// TestUnmarshalWellKnownCommunity validates decoding of IANA well-known
// communities from the COMMUNITIES attribute value.
func TestUnmarshalWellKnownCommunity(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect []string
	}{
		{
			name:   "BLACKHOLE RFC7999",
			input:  packCommunities(0xFFFF029A),
			expect: []string{"BLACKHOLE"},
		},
		{
			name:   "NO_EXPORT RFC1997",
			input:  packCommunities(0xFFFFFF01),
			expect: []string{"NO_EXPORT"},
		},
		{
			name:   "GRACEFUL_SHUTDOWN RFC8326",
			input:  packCommunities(0xFFFF0000),
			expect: []string{"GRACEFUL_SHUTDOWN"},
		},
		{
			name:   "mixed well-known and regular keeps wire order, names only",
			input:  packCommunities(0xFFFF029A, 0xFC000064, 0xFFFFFF01),
			expect: []string{"BLACKHOLE", "NO_EXPORT"},
		},
		{
			name:   "duplicate well-known preserved",
			input:  packCommunities(0xFFFF029A, 0xFFFF029A),
			expect: []string{"BLACKHOLE", "BLACKHOLE"},
		},
		{
			name:   "no well-known present returns nil",
			input:  packCommunities(0x0000FDE8, 0x19350056),
			expect: nil,
		},
		{
			name:   "unassigned well-known value returns nil",
			input:  packCommunities(0xFFFF0FFF),
			expect: nil,
		},
		{
			name:   "draft-only value not registered returns nil",
			input:  packCommunities(0xFFFF0002),
			expect: nil,
		},
		{
			name:   "empty input returns nil",
			input:  []byte{},
			expect: nil,
		},
		{
			name:   "nil input returns nil",
			input:  nil,
			expect: nil,
		},
		{
			name:   "length not a multiple of 4 returns nil",
			input:  []byte{0xFF, 0xFF, 0x02},
			expect: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unmarshalWellKnownCommunity(tt.input)
			if !reflect.DeepEqual(got, tt.expect) {
				t.Errorf("unmarshalWellKnownCommunity() = %v, want %v", got, tt.expect)
			}
		})
	}
}

// TestWellKnownCommunitiesRegistry checks the decoder against an independent
// table of expected IANA code point -> name mappings (verbatim from the IANA
// "BGP Well-known Communities" registry) so a wrong value or name is caught.
func TestWellKnownCommunitiesRegistry(t *testing.T) {
	want := map[uint32]string{
		0xFFFF0000: "GRACEFUL_SHUTDOWN",   // RFC 8326
		0xFFFF0001: "ACCEPT_OWN",          // RFC 7611
		0xFFFF0006: "LLGR_STALE",          // RFC 9494
		0xFFFF0007: "NO_LLGR",             // RFC 9494
		0xFFFF0009: "Standby PE",          // RFC 9026
		0xFFFF029A: "BLACKHOLE",           // RFC 7999
		0xFFFFFF01: "NO_EXPORT",           // RFC 1997
		0xFFFFFF02: "NO_ADVERTISE",        // RFC 1997
		0xFFFFFF03: "NO_EXPORT_SUBCONFED", // RFC 1997
		0xFFFFFF04: "NOPEER",              // RFC 3765
	}
	if len(wellKnownCommunities) != len(want) {
		t.Errorf("registry has %d entries, want %d", len(wellKnownCommunities), len(want))
	}
	for value, name := range want {
		got := unmarshalWellKnownCommunity(packCommunities(value))
		if len(got) != 1 || got[0] != name {
			t.Errorf("value 0x%08X decoded to %v, want [%q]", value, got, name)
		}
	}
}

// TestUnmarshalBaseAttributes_WellKnownCommunity verifies that a full
// COMMUNITIES path attribute yields both the numeric CommunityList (unchanged,
// backward compatible) and the symbolic WellKnownCommunityList.
func TestUnmarshalBaseAttributes_WellKnownCommunity(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantComm []string
		wantWK   []string
	}{
		{
			// Flags 0xC0 (optional transitive), Type 0x08 (COMMUNITIES), Len 0x08,
			// value = BLACKHOLE (0xFFFF029A) + 64512:100 (0xFC000064).
			name:     "blackhole plus regular",
			input:    []byte{0xC0, 0x08, 0x08, 0xFF, 0xFF, 0x02, 0x9A, 0xFC, 0x00, 0x00, 0x64},
			wantComm: []string{"65535:666", "64512:100"},
			wantWK:   []string{"BLACKHOLE"},
		},
		{
			// Only regular/private communities: 64512:100 + 64512:200.
			name:     "regular only leaves well-known nil",
			input:    []byte{0xC0, 0x08, 0x08, 0xFC, 0x00, 0x00, 0x64, 0xFC, 0x00, 0x00, 0xC8},
			wantComm: []string{"64512:100", "64512:200"},
			wantWK:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBGPBaseAttributes(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got.CommunityList, tt.wantComm) {
				t.Errorf("CommunityList = %v, want %v", got.CommunityList, tt.wantComm)
			}
			if !reflect.DeepEqual(got.WellKnownCommunityList, tt.wantWK) {
				t.Errorf("WellKnownCommunityList = %v, want %v", got.WellKnownCommunityList, tt.wantWK)
			}
		})
	}
}

// TestBaseAttrHash_ExcludesWellKnownCommunity guards backward compatibility: the
// derived WellKnownCommunityList must not influence base_attr_hash. The hash is
// computed over the raw path-attribute bytes, so a derived struct field cannot
// affect it.
func TestBaseAttrHash_ExcludesWellKnownCommunity(t *testing.T) {
	// One COMMUNITIES attribute: flags 0xC0, type 0x08, len 0x04, value = BLACKHOLE
	// (0xFFFF029A). The raw attribute value hashed is {0xFF, 0xFF, 0x02, 0x9A}.
	input := []byte{0xC0, 0x08, 0x04, 0xFF, 0xFF, 0x02, 0x9A}
	got, err := UnmarshalBGPBaseAttributes(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.WellKnownCommunityList) == 0 {
		t.Fatalf("precondition failed: WellKnownCommunityList should be populated")
	}
	// base_attr_hash is the MD5 of the raw attribute value bytes; the derived
	// field must not leak into it.
	h := md5.New()
	h.Write([]byte{0xFF, 0xFF, 0x02, 0x9A})
	want := hex.EncodeToString(h.Sum(nil))
	if got.BaseAttrHash != want {
		t.Errorf("BaseAttrHash = %q, want %q (derived field must not affect hash)", got.BaseAttrHash, want)
	}
}

// TestBaseAttributes_Equal_IgnoresWellKnownCommunity verifies that the derived
// WellKnownCommunityList does not affect equality, consistent with BaseAttrHash
// also being excluded from Equal.
func TestBaseAttributes_Equal_IgnoresWellKnownCommunity(t *testing.T) {
	a := &BaseAttributes{
		CommunityList:          []string{"65535:666"},
		WellKnownCommunityList: []string{"BLACKHOLE"},
	}
	b := &BaseAttributes{
		CommunityList:          []string{"65535:666"},
		WellKnownCommunityList: nil,
	}
	if eq, diffs := a.Equal(b); !eq {
		t.Errorf("Equal() = false (diffs=%v), want true; WellKnownCommunityList must not affect equality", diffs)
	}
}
