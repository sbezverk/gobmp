package bgp

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

// buildPathAttr constructs a single BGP path attribute in wire format.
// flags is the attribute type flags byte, attrType is the attribute type code,
// and value is the attribute value payload. Extended-length (flag bit 0x10)
// is used when len(value) > 255.
func buildPathAttr(flags uint8, attrType uint8, value []byte) []byte {
	if len(value) > 255 {
		flags |= 0x10 // set extended-length
	}
	var b []byte
	if flags&0x10 != 0 {
		b = make([]byte, 4+len(value))
		b[0] = flags
		b[1] = attrType
		binary.BigEndian.PutUint16(b[2:4], uint16(len(value)))
		copy(b[4:], value)
	} else {
		b = make([]byte, 3+len(value))
		b[0] = flags
		b[1] = attrType
		b[2] = byte(len(value))
		copy(b[3:], value)
	}
	return b
}

// buildAttrSetValue constructs the ATTR_SET attribute value (Origin AS + embedded path attrs).
func buildAttrSetValue(originAS uint32, embeddedAttrs ...[]byte) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b[:4], originAS)
	for _, attr := range embeddedAttrs {
		b = append(b, attr...)
	}
	return b
}

func TestUnmarshalAttrSet_ValidOriginASOnly(t *testing.T) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, 65001)

	as, err := UnmarshalAttrSet(b)
	if err != nil {
		t.Fatalf("UnmarshalAttrSet failed: %v", err)
	}
	if as.OriginAS != 65001 {
		t.Errorf("expected OriginAS 65001, got %d", as.OriginAS)
	}
	if as.PathAttributes != nil {
		t.Errorf("expected nil PathAttributes for Origin-AS-only ATTR_SET, got %+v", as.PathAttributes)
	}
}

func TestUnmarshalAttrSet_ValidWithOriginAttr(t *testing.T) {
	// Embed an ORIGIN attribute (type 1, flags 0x40, value 0x00 = IGP)
	originAttr := buildPathAttr(0x40, 1, []byte{0x00})
	value := buildAttrSetValue(65002, originAttr)

	as, err := UnmarshalAttrSet(value)
	if err != nil {
		t.Fatalf("UnmarshalAttrSet failed: %v", err)
	}
	if as.OriginAS != 65002 {
		t.Errorf("expected OriginAS 65002, got %d", as.OriginAS)
	}
	if as.PathAttributes == nil {
		t.Fatal("expected non-nil PathAttributes")
	}
	if as.PathAttributes.Origin != "igp" {
		t.Errorf("expected origin igp, got %q", as.PathAttributes.Origin)
	}
}

func TestUnmarshalAttrSet_ValidWithMultipleAttrs(t *testing.T) {
	// Embed: ORIGIN (igp) + MED (100) + LOCAL_PREF (200)
	originAttr := buildPathAttr(0x40, 1, []byte{0x00})
	medVal := make([]byte, 4)
	binary.BigEndian.PutUint32(medVal, 100)
	medAttr := buildPathAttr(0x80, 4, medVal)
	lpVal := make([]byte, 4)
	binary.BigEndian.PutUint32(lpVal, 200)
	lpAttr := buildPathAttr(0x40, 5, lpVal)

	value := buildAttrSetValue(64512, originAttr, medAttr, lpAttr)

	as, err := UnmarshalAttrSet(value)
	if err != nil {
		t.Fatalf("UnmarshalAttrSet failed: %v", err)
	}
	if as.OriginAS != 64512 {
		t.Errorf("expected OriginAS 64512, got %d", as.OriginAS)
	}
	pa := as.PathAttributes
	if pa == nil {
		t.Fatal("expected non-nil PathAttributes")
	}
	if pa.Origin != "igp" {
		t.Errorf("expected origin igp, got %q", pa.Origin)
	}
	if pa.MED != 100 {
		t.Errorf("expected MED 100, got %d", pa.MED)
	}
	if pa.LocalPref != 200 {
		t.Errorf("expected LocalPref 200, got %d", pa.LocalPref)
	}
}

func TestUnmarshalAttrSet_ValidWithASPath(t *testing.T) {
	// Embed: ORIGIN (egp) + AS_PATH with one AS4 segment [65001, 65002]
	originAttr := buildPathAttr(0x40, 1, []byte{0x01})
	// AS_PATH: segment type 0x02 (AS_SEQUENCE), length 2, two 4-byte ASNs
	asPathVal := []byte{0x02, 0x02}
	as1 := make([]byte, 4)
	binary.BigEndian.PutUint32(as1, 65001)
	as2 := make([]byte, 4)
	binary.BigEndian.PutUint32(as2, 65002)
	asPathVal = append(asPathVal, as1...)
	asPathVal = append(asPathVal, as2...)
	asPathAttr := buildPathAttr(0x40, 2, asPathVal)

	value := buildAttrSetValue(65500, originAttr, asPathAttr)

	as, err := UnmarshalAttrSet(value)
	if err != nil {
		t.Fatalf("UnmarshalAttrSet failed: %v", err)
	}
	if as.OriginAS != 65500 {
		t.Errorf("expected OriginAS 65500, got %d", as.OriginAS)
	}
	pa := as.PathAttributes
	if pa == nil {
		t.Fatal("expected non-nil PathAttributes")
	}
	if pa.Origin != "egp" {
		t.Errorf("expected origin egp, got %q", pa.Origin)
	}
	expected := []uint32{65001, 65002}
	if !reflect.DeepEqual(pa.ASPath, expected) {
		t.Errorf("expected ASPath %v, got %v", expected, pa.ASPath)
	}
	if pa.ASPathCount != 2 {
		t.Errorf("expected ASPathCount 2, got %d", pa.ASPathCount)
	}
}

func TestUnmarshalAttrSet_ValidWithCommunities(t *testing.T) {
	// Embed: communities 65001:100 and 65001:200
	comm := make([]byte, 8)
	binary.BigEndian.PutUint32(comm[0:4], 65001<<16|100)
	binary.BigEndian.PutUint32(comm[4:8], 65001<<16|200)
	commAttr := buildPathAttr(0xc0, 8, comm)

	value := buildAttrSetValue(65001, commAttr)

	as, err := UnmarshalAttrSet(value)
	if err != nil {
		t.Fatalf("UnmarshalAttrSet failed: %v", err)
	}
	pa := as.PathAttributes
	if pa == nil {
		t.Fatal("expected non-nil PathAttributes")
	}
	if len(pa.CommunityList) != 2 {
		t.Fatalf("expected 2 communities, got %d", len(pa.CommunityList))
	}
	if pa.CommunityList[0] != "65001:100" {
		t.Errorf("expected community 65001:100, got %s", pa.CommunityList[0])
	}
	if pa.CommunityList[1] != "65001:200" {
		t.Errorf("expected community 65001:200, got %s", pa.CommunityList[1])
	}
}

func TestUnmarshalAttrSet_TooShort(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0x00}},
		{"3 bytes", []byte{0x00, 0x00, 0x01}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalAttrSet(tt.input)
			if err == nil {
				t.Fatal("expected error for too-short input, got nil")
			}
		})
	}
}

func TestUnmarshalAttrSet_TruncatedEmbeddedAttr(t *testing.T) {
	// Origin AS (4 bytes) + truncated path attr header (1 byte instead of 2+)
	b := make([]byte, 5)
	binary.BigEndian.PutUint32(b[:4], 65001)
	b[4] = 0x40 // flags byte only, missing type byte

	_, err := UnmarshalAttrSet(b)
	if err == nil {
		t.Fatal("expected error for truncated embedded attribute, got nil")
	}
}

func TestUnmarshalAttrSet_ForbiddenMPReachNLRI(t *testing.T) {
	// Embed MP_REACH_NLRI (type 14) - must be rejected
	mpReach := buildPathAttr(0x90, 14, []byte{0x00, 0x01, 0x01, 0x04, 0x0a, 0x00, 0x00, 0x01, 0x00})
	value := buildAttrSetValue(65001, mpReach)

	_, err := UnmarshalAttrSet(value)
	if err == nil {
		t.Fatal("expected error for MP_REACH_NLRI inside ATTR_SET, got nil")
	}
}

func TestUnmarshalAttrSet_ForbiddenMPUnreachNLRI(t *testing.T) {
	// Embed MP_UNREACH_NLRI (type 15) - must be rejected
	mpUnreach := buildPathAttr(0x90, 15, []byte{0x00, 0x01, 0x01, 0x18, 0x0a, 0x00, 0x01})
	value := buildAttrSetValue(65001, mpUnreach)

	_, err := UnmarshalAttrSet(value)
	if err == nil {
		t.Fatal("expected error for MP_UNREACH_NLRI inside ATTR_SET, got nil")
	}
}

func TestUnmarshalAttrSet_ForbiddenNestedAttrSet(t *testing.T) {
	// Embed another ATTR_SET (type 128) - must be rejected (no recursion)
	innerAttrSet := buildPathAttr(0xc0, 128, []byte{0x00, 0x00, 0xfd, 0xe9})
	value := buildAttrSetValue(65001, innerAttrSet)

	_, err := UnmarshalAttrSet(value)
	if err == nil {
		t.Fatal("expected error for nested ATTR_SET, got nil")
	}
}

func TestUnmarshalAttrSet_OriginASZero(t *testing.T) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, 0)

	as, err := UnmarshalAttrSet(b)
	if err != nil {
		t.Fatalf("UnmarshalAttrSet failed: %v", err)
	}
	if as.OriginAS != 0 {
		t.Errorf("expected OriginAS 0, got %d", as.OriginAS)
	}
}

func TestUnmarshalAttrSet_OriginASMaxUint32(t *testing.T) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, 0xFFFFFFFF)

	as, err := UnmarshalAttrSet(b)
	if err != nil {
		t.Fatalf("UnmarshalAttrSet failed: %v", err)
	}
	if as.OriginAS != 0xFFFFFFFF {
		t.Errorf("expected OriginAS 4294967295, got %d", as.OriginAS)
	}
}

func TestUnmarshalAttrSet_ValidAtomicAggregate(t *testing.T) {
	// Embed: ATOMIC_AGGREGATE (type 6, empty value)
	atomicAgg := buildPathAttr(0x40, 6, []byte{})
	value := buildAttrSetValue(65001, atomicAgg)

	as, err := UnmarshalAttrSet(value)
	if err != nil {
		t.Fatalf("UnmarshalAttrSet failed: %v", err)
	}
	if as.PathAttributes == nil {
		t.Fatal("expected non-nil PathAttributes")
	}
	if !as.PathAttributes.IsAtomicAgg {
		t.Error("expected IsAtomicAgg=true")
	}
}

func TestUnmarshalAttrSet_DeprecatedAttrsSkipped(t *testing.T) {
	// Embed deprecated DPA (type 11) + ORIGIN (igp) - deprecated attr should be silently skipped
	dpaAttr := buildPathAttr(0xc0, 11, []byte{0x00, 0x01, 0x00, 0x02})
	originAttr := buildPathAttr(0x40, 1, []byte{0x00})
	value := buildAttrSetValue(65001, dpaAttr, originAttr)

	as, err := UnmarshalAttrSet(value)
	if err != nil {
		t.Fatalf("UnmarshalAttrSet failed: %v", err)
	}
	if as.PathAttributes == nil {
		t.Fatal("expected non-nil PathAttributes")
	}
	if as.PathAttributes.Origin != "igp" {
		t.Errorf("expected origin igp, got %q", as.PathAttributes.Origin)
	}
}

func TestBaseAttributes_Equal_AttrSet(t *testing.T) {
	tests := []struct {
		name        string
		a           *BaseAttributes
		b           *BaseAttributes
		isEqual     bool
		diffSubstr  string
	}{
		{
			name:    "both nil",
			a:       &BaseAttributes{AttrSet: nil},
			b:       &BaseAttributes{AttrSet: nil},
			isEqual: true,
		},
		{
			name:       "one nil one non-nil",
			a:          &BaseAttributes{AttrSet: &AttrSet{OriginAS: 65001}},
			b:          &BaseAttributes{AttrSet: nil},
			isEqual:    false,
			diffSubstr: "attr_set mismatch",
		},
		{
			name:    "same OriginAS no attrs",
			a:       &BaseAttributes{AttrSet: &AttrSet{OriginAS: 65001}},
			b:       &BaseAttributes{AttrSet: &AttrSet{OriginAS: 65001}},
			isEqual: true,
		},
		{
			name:       "different OriginAS",
			a:          &BaseAttributes{AttrSet: &AttrSet{OriginAS: 65001}},
			b:          &BaseAttributes{AttrSet: &AttrSet{OriginAS: 65002}},
			isEqual:    false,
			diffSubstr: "origin_as mismatch",
		},
		{
			name: "same embedded attrs different BaseAttrHash",
			a: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS: 65001,
				PathAttributes: &BaseAttributes{
					BaseAttrHash: "aaa",
					Origin:       "igp",
					MED:          100,
				},
			}},
			b: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS: 65001,
				PathAttributes: &BaseAttributes{
					BaseAttrHash: "bbb",
					Origin:       "igp",
					MED:          100,
				},
			}},
			isEqual: true,
		},
		{
			name: "embedded communities different order equal semantics",
			a: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS: 65001,
				PathAttributes: &BaseAttributes{
					CommunityList: []string{"65001:200", "65001:100"},
				},
			}},
			b: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS: 65001,
				PathAttributes: &BaseAttributes{
					CommunityList: []string{"65001:100", "65001:200"},
				},
			}},
			isEqual: true,
		},
		{
			name: "embedded AS_PATH different order equal semantics",
			a: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS: 65001,
				PathAttributes: &BaseAttributes{
					ASPath:      []uint32{65002, 65001},
					ASPathCount: 2,
				},
			}},
			b: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS: 65001,
				PathAttributes: &BaseAttributes{
					ASPath:      []uint32{65001, 65002},
					ASPathCount: 2,
				},
			}},
			isEqual: true,
		},
		{
			name: "embedded ext_community different order equal semantics",
			a: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS: 65001,
				PathAttributes: &BaseAttributes{
					ExtCommunityList: []string{"rt=65001:100", "rt=65001:200"},
				},
			}},
			b: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS: 65001,
				PathAttributes: &BaseAttributes{
					ExtCommunityList: []string{"rt=65001:200", "rt=65001:100"},
				},
			}},
			isEqual: true,
		},
		{
			name: "embedded large_community different order equal semantics",
			a: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS: 65001,
				PathAttributes: &BaseAttributes{
					LgCommunityList: []string{"65001:0:200", "65001:0:100"},
				},
			}},
			b: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS: 65001,
				PathAttributes: &BaseAttributes{
					LgCommunityList: []string{"65001:0:100", "65001:0:200"},
				},
			}},
			isEqual: true,
		},
		{
			name: "embedded different MED",
			a: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS:       65001,
				PathAttributes: &BaseAttributes{MED: 100},
			}},
			b: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS:       65001,
				PathAttributes: &BaseAttributes{MED: 200},
			}},
			isEqual:    false,
			diffSubstr: "med mismatch",
		},
		{
			name: "one embedded nil one non-nil",
			a: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS:       65001,
				PathAttributes: &BaseAttributes{Origin: "igp"},
			}},
			b: &BaseAttributes{AttrSet: &AttrSet{
				OriginAS:       65001,
				PathAttributes: nil,
			}},
			isEqual:    false,
			diffSubstr: "path_attributes mismatch",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			eq, diffs := tt.a.Equal(tt.b)
			if eq != tt.isEqual {
				t.Errorf("expected Equal=%v, got %v (diffs: %v)", tt.isEqual, eq, diffs)
			}
			if !tt.isEqual && tt.diffSubstr != "" {
				found := false
				for _, d := range diffs {
					if strings.Contains(d, tt.diffSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected diff containing %q in diffs %v", tt.diffSubstr, diffs)
				}
			}
		})
	}
}

func TestUnmarshalAttrSet_EndToEndViaBaseAttributes(t *testing.T) {
	// Build a full BGP path attribute buffer that contains an ATTR_SET (type 128).
	// The ATTR_SET value: OriginAS=65001 + embedded ORIGIN(igp) + MED(42)
	originAttr := buildPathAttr(0x40, 1, []byte{0x00})
	medVal := make([]byte, 4)
	binary.BigEndian.PutUint32(medVal, 42)
	medAttr := buildPathAttr(0x80, 4, medVal)
	attrSetValue := buildAttrSetValue(65001, originAttr, medAttr)

	// Wrap in a top-level path attribute with type 128, optional+transitive flags (0xC0)
	topLevelAttrSet := buildPathAttr(0xC0, 128, attrSetValue)

	// Also add a top-level ORIGIN attribute (incomplete)
	topLevelOrigin := buildPathAttr(0x40, 1, []byte{0x02})

	// Concatenate top-level attrs
	fullBuf := append(topLevelOrigin, topLevelAttrSet...)

	ba, err := UnmarshalBGPBaseAttributes(fullBuf)
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes failed: %v", err)
	}
	if ba.Origin != "incomplete" {
		t.Errorf("expected top-level origin incomplete, got %q", ba.Origin)
	}
	if ba.AttrSet == nil {
		t.Fatal("expected non-nil AttrSet in BaseAttributes")
	}
	if ba.AttrSet.OriginAS != 65001 {
		t.Errorf("expected AttrSet.OriginAS 65001, got %d", ba.AttrSet.OriginAS)
	}
	if ba.AttrSet.PathAttributes == nil {
		t.Fatal("expected non-nil embedded PathAttributes")
	}
	if ba.AttrSet.PathAttributes.Origin != "igp" {
		t.Errorf("expected embedded origin igp, got %q", ba.AttrSet.PathAttributes.Origin)
	}
	if ba.AttrSet.PathAttributes.MED != 42 {
		t.Errorf("expected embedded MED 42, got %d", ba.AttrSet.PathAttributes.MED)
	}
}

func TestUnmarshalAttrSet_CorruptedEmbeddedLength(t *testing.T) {
	// Origin AS + embedded attr with length field claiming more bytes than available
	b := make([]byte, 4+4) // 4 Origin AS + 4 attr header bytes
	binary.BigEndian.PutUint32(b[:4], 65001)
	b[4] = 0x40 // flags
	b[5] = 1    // type (ORIGIN)
	b[6] = 100  // length claims 100 bytes but only 1 remains
	b[7] = 0x00

	_, err := UnmarshalAttrSet(b)
	if err == nil {
		t.Fatal("expected error for corrupted embedded attribute length, got nil")
	}
}
