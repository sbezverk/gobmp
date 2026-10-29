package bgp

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func peEntry(ip string, label [3]byte) []byte {
	return append(netip.MustParseAddr(ip).AsSlice(), label[:]...)
}

func peEntries(n int, ipv6 bool) []byte {
	var out []byte
	for i := 0; i < n; i++ {
		if ipv6 {
			a := netip.MustParseAddr("2001:db8::1").As16()
			a[15] = byte(i + 1)
			out = append(append(out, a[:]...), 0, 1, 0)
		} else {
			out = append(out, 10, 0, 0, byte(i+1), 0, 1, 0)
		}
	}
	return out
}

func peAttr(v []byte) PathAttribute {
	return PathAttribute{AttributeTypeFlags: 0xc0, AttributeType: 27, AttributeLength: uint16(len(v)), Attribute: v}
}

// reachWith wraps raw MCAST-VPN NLRI bytes into an MP_REACH_NLRI (AFI 1, SAFI 5) attribute.
func reachWith(nlri []byte) PathAttribute {
	v := append([]byte{0, 1, 5, 4, 192, 0, 2, 254, 0}, nlri...)
	return PathAttribute{AttributeTypeFlags: 0x80, AttributeType: 14, AttributeLength: uint16(len(v)), Attribute: v}
}

func originator(ipv6 bool) []byte {
	if ipv6 {
		a := netip.MustParseAddr("2001:db8::99").As16()
		return a[:]
	}
	return []byte{192, 0, 2, 1}
}

var zeroRD = make([]byte, 8)

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// type1NLRI is an Intra-AS I-PMSI A-D route.
func type1NLRI(orig []byte) []byte {
	return cat([]byte{1, byte(8 + len(orig))}, zeroRD, orig)
}

// mvpnReach builds an MP_REACH_NLRI (SAFI 5) holding one Intra-AS I-PMSI A-D route.
func mvpnReach(ipv6Originator bool) PathAttribute {
	return reachWith(type1NLRI(originator(ipv6Originator)))
}

func TestPEDistinguisherLabels(t *testing.T) {
	v4One := peEntry("192.0.2.1", [3]byte{0x00, 0x01, 0x00})
	v6One := peEntry("2001:db8::1", [3]byte{0x00, 0x20, 0x00})
	// type 3 (S-PMSI): RD + src len 0 + group len 0 + originator.
	type3 := func(orig []byte) PathAttribute {
		return reachWith(cat([]byte{3, byte(10 + len(orig))}, zeroRD, []byte{0, 0}, orig))
	}
	// type 4 (Leaf A-D): Route Key (embedded type 1 route, IPv4) + outer originator.
	type4 := func(orig []byte) PathAttribute {
		key := type1NLRI([]byte{10, 9, 9, 9})
		return reachWith(cat([]byte{4, byte(len(key) + len(orig))}, key, orig))
	}
	// type 2 (Inter-AS I-PMSI): RD + source AS, no originator.
	type2 := reachWith(cat([]byte{2, 12}, zeroRD, []byte{0, 0, 0xfd, 0xe8}))

	tests := []struct {
		name  string
		attrs []PathAttribute
		want  []PEDistinguisherLabel
	}{
		{"ipv4 single", []PathAttribute{peAttr(v4One)}, []PEDistinguisherLabel{{PEAddress: "192.0.2.1", Label: 0x10}}},
		{"ipv4 multiple", []PathAttribute{peAttr(cat(v4One, peEntry("198.51.100.7", [3]byte{0xff, 0xff, 0xf0})))},
			[]PEDistinguisherLabel{{PEAddress: "192.0.2.1", Label: 0x10}, {PEAddress: "198.51.100.7", Label: 0xfffff}}},
		{"ipv6 single", []PathAttribute{peAttr(v6One)}, []PEDistinguisherLabel{{PEAddress: "2001:db8::1", Label: 0x200}}},
		{"ipv4-mapped ipv6 keeps ipv6 form", []PathAttribute{peAttr(peEntry("::ffff:192.0.2.1", [3]byte{0x00, 0x20, 0x00})), mvpnReach(true)},
			[]PEDistinguisherLabel{{PEAddress: "::ffff:192.0.2.1", Label: 0x200}}},
		{"label low 4 bits ignored", []PathAttribute{peAttr(peEntry("192.0.2.1", [3]byte{0x00, 0x00, 0x1f}))}, []PEDistinguisherLabel{{PEAddress: "192.0.2.1", Label: 1}}},
		{"empty value", []PathAttribute{peAttr(nil)}, nil},
		{"wrong length", []PathAttribute{peAttr(v4One[:6])}, nil},
		{"ipv4 multicast", []PathAttribute{peAttr(peEntry("224.0.0.1", [3]byte{}))}, nil},
		{"ipv4 unspecified", []PathAttribute{peAttr(peEntry("0.0.0.0", [3]byte{}))}, nil},
		{"ipv4 broadcast", []PathAttribute{peAttr(peEntry("255.255.255.255", [3]byte{}))}, nil},
		{"ipv6 multicast", []PathAttribute{peAttr(peEntry("ff02::1", [3]byte{}))}, nil},
		{"ipv6 unspecified", []PathAttribute{peAttr(peEntry("::", [3]byte{}))}, nil},
		{"one bad entry rejects all", []PathAttribute{peAttr(cat(v4One, peEntry("224.0.0.1", [3]byte{})))}, nil},
		{"ambiguous 133 without nlri", []PathAttribute{peAttr(peEntries(19, false))}, nil},
		{"neither multiple", []PathAttribute{peAttr(make([]byte, 8))}, nil},
		{"nlri ipv6 but ipv4 data", []PathAttribute{peAttr(v4One), mvpnReach(true)}, nil},
		{"nlri ipv4 but ipv6 data", []PathAttribute{peAttr(v6One), mvpnReach(false)}, nil},
		{"nlri ipv4 agrees, attr first", []PathAttribute{peAttr(v4One), mvpnReach(false)}, []PEDistinguisherLabel{{PEAddress: "192.0.2.1", Label: 0x10}}},
		{"nlri ipv6 agrees, attr last", []PathAttribute{mvpnReach(true), peAttr(v6One)}, []PEDistinguisherLabel{{PEAddress: "2001:db8::1", Label: 0x200}}},
		{"type 3 originator ipv6", []PathAttribute{type3(originator(true)), peAttr(v6One)}, []PEDistinguisherLabel{{PEAddress: "2001:db8::1", Label: 0x200}}},
		{"type 3 originator ipv4 vs ipv6 data", []PathAttribute{type3(originator(false)), peAttr(v6One)}, nil},
		{"type 4 outer originator ipv6 decides", []PathAttribute{type4(originator(true)), peAttr(v6One)}, []PEDistinguisherLabel{{PEAddress: "2001:db8::1", Label: 0x200}}},
		{"type 4 outer originator ipv6 rejects ipv4 data", []PathAttribute{type4(originator(true)), peAttr(v4One)}, nil},
		{"type 2 only nlri falls back to length (ipv4)", []PathAttribute{type2, peAttr(v4One)}, []PEDistinguisherLabel{{PEAddress: "192.0.2.1", Label: 0x10}}},
		{"type 2 only nlri falls back to length (ipv6)", []PathAttribute{type2, peAttr(v6One)}, []PEDistinguisherLabel{{PEAddress: "2001:db8::1", Label: 0x200}}},
		{"type 2 only nlri, ambiguous length", []PathAttribute{type2, peAttr(peEntries(19, false))}, nil},
		{"garbage mp_reach falls back to length", []PathAttribute{{AttributeType: 14, Attribute: []byte{0}}, peAttr(v4One)}, []PEDistinguisherLabel{{PEAddress: "192.0.2.1", Label: 0x10}}},
		{"non-mcastvpn mp_reach falls back", []PathAttribute{{AttributeType: 14, Attribute: []byte{0, 1, 1, 4, 1, 1, 1, 1, 0}}, peAttr(v6One)}, []PEDistinguisherLabel{{PEAddress: "2001:db8::1", Label: 0x200}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ba, err := unmarshalBaseAttrsFromSlice(tt.attrs, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ba.PEDistinguisherLabels, tt.want) {
				t.Fatalf("got %+v want %+v", ba.PEDistinguisherLabels, tt.want)
			}
		})
	}
}

func TestPEDistinguisherLabelsAmbiguousResolvedByNLRI(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		reach    PathAttribute
		wantN    int
		wantAddr string
	}{
		{"133 bytes ipv4 (19 entries)", peEntries(19, false), mvpnReach(false), 19, "10.0.0.1"},
		{"133 bytes ipv6 (7 entries)", peEntries(7, true), mvpnReach(true), 7, "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.data) != 133 {
				t.Fatalf("test data len %d", len(tt.data))
			}
			for _, attrs := range [][]PathAttribute{{peAttr(tt.data), tt.reach}, {tt.reach, peAttr(tt.data)}} {
				ba, err := unmarshalBaseAttrsFromSlice(attrs, nil)
				if err != nil {
					t.Fatal(err)
				}
				if len(ba.PEDistinguisherLabels) != tt.wantN || ba.PEDistinguisherLabels[0].PEAddress != tt.wantAddr || ba.PEDistinguisherLabels[0].Label != 0x10 {
					t.Fatalf("got %+v", ba.PEDistinguisherLabels)
				}
			}
		})
	}
}

func TestUnmarshalPEDistinguisherLabelsDirect(t *testing.T) {
	v4 := peEntry("192.0.2.1", [3]byte{0, 1, 0})
	v6 := peEntry("2001:db8::1", [3]byte{0, 1, 0})
	none := func() int { return 0 }
	tests := []struct {
		name    string
		b       []byte
		orig    func() int
		want    []PEDistinguisherLabel
		wantN   int
		wantErr bool
	}{
		{"ipv4", v4, none, []PEDistinguisherLabel{{PEAddress: "192.0.2.1", Label: 0x10}}, 1, false},
		{"ipv6", v6, none, []PEDistinguisherLabel{{PEAddress: "2001:db8::1", Label: 0x10}}, 1, false},
		{"originator forces ipv6 on ambiguous length", peEntries(7, true), func() int { return 16 }, nil, 7, false},
		{"originator ipv6, ipv4 sized data", v4, func() int { return 16 }, nil, 0, true},
		{"empty", nil, none, nil, 0, true},
		{"neither multiple", make([]byte, 8), none, nil, 0, true},
		{"ambiguous", peEntries(19, false), none, nil, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unmarshalPEDistinguisherLabels(tt.b, tt.orig)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %t", err, tt.wantErr)
			}
			if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v want %+v", got, tt.want)
			}
			if tt.wantErr && got != nil {
				t.Fatalf("expected nil on error, got %+v", got)
			}
			if len(got) != tt.wantN {
				t.Fatalf("expected %d entries, got %d", tt.wantN, len(got))
			}
		})
	}
}

func TestPEDistinguisherLabelsLookupAtMostOncePerUpdate(t *testing.T) {
	orig := lookupOriginatorLen
	t.Cleanup(func() { lookupOriginatorLen = orig })
	calls := 0
	lookupOriginatorLen = func(attrs []PathAttribute) int {
		calls++
		return orig(attrs)
	}
	v4 := peEntry("192.0.2.1", [3]byte{0, 1, 0})
	build := func(v ...[]byte) []PathAttribute {
		attrs := []PathAttribute{mvpnReach(false)}
		for _, b := range v {
			attrs = append(attrs, peAttr(b))
		}
		return attrs
	}
	many := func(n int, b []byte) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = b
		}
		return out
	}
	tests := []struct {
		name      string
		attrs     []PathAttribute
		wantCalls int
	}{
		{"repeated empty attr 27: no lookup", build(many(100, nil)...), 0},
		{"repeated wrong-multiple attr 27: no lookup", build(many(100, make([]byte, 8))...), 0},
		{"repeated valid attr 27: one lookup", build(many(100, v4)...), 1},
		{"empty then valid: one lookup", build(append(many(50, nil), many(50, v4)...)...), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls = 0
			if _, err := unmarshalBaseAttrsFromSlice(tt.attrs, nil); err != nil {
				t.Fatal(err)
			}
			if calls != tt.wantCalls {
				t.Fatalf("lookup calls = %d, want %d", calls, tt.wantCalls)
			}
		})
	}
}

func TestPEDistinguisherLabelsJSONAndEqual(t *testing.T) {
	ba, err := unmarshalBaseAttrsFromSlice([]PathAttribute{peAttr(peEntry("192.0.2.1", [3]byte{0, 0x10, 0}))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.Marshal(ba)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(j), `"pe_distinguisher_labels":[{"pe_address":"192.0.2.1","label":256}]`) {
		t.Fatalf("json: %s", j)
	}
	none, err := unmarshalBaseAttrsFromSlice(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	j, err = json.Marshal(none)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(j), "pe_distinguisher_labels") {
		t.Fatalf("key present when empty: %s", j)
	}
	if eq, _ := ba.Equal(ba); !eq {
		t.Fatal("same should be equal")
	}
	if eq, diffs := ba.Equal(none); eq || !strings.Contains(strings.Join(diffs, ","), "pe_distinguisher_labels") {
		t.Fatalf("expected mismatch, got %v %v", eq, diffs)
	}
}
