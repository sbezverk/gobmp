package bgp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func dPathTestSegment(domains ...DPathDomain) []byte {
	b := make([]byte, 1+7*len(domains))
	b[0] = byte(len(domains))
	for i, domain := range domains {
		p := 1 + i*7
		binary.BigEndian.PutUint32(b[p:p+4], domain.GlobalAdmin)
		binary.BigEndian.PutUint16(b[p+4:p+6], domain.LocalAdmin)
		b[p+6] = domain.ISFSAFIType
	}
	return b
}

func TestUnmarshalDPath(t *testing.T) {
	domain1 := DPathDomain{GlobalAdmin: 65000, LocalAdmin: 1, ISFSAFIType: 70}
	domain2 := DPathDomain{GlobalAdmin: 4200000000, LocalAdmin: 2, ISFSAFIType: 128}
	unknown := DPathDomain{GlobalAdmin: 0xffffffff, LocalAdmin: 0xffff, ISFSAFIType: 255}
	maximum := make([]DPathDomain, 255)
	for i := range maximum {
		maximum[i] = DPathDomain{GlobalAdmin: uint32(i), LocalAdmin: uint16(i), ISFSAFIType: uint8(i)}
	}
	tests := []struct {
		name  string
		input []byte
		want  []DPathSegment
	}{
		{"single", dPathTestSegment(domain1), []DPathSegment{{Domains: []DPathDomain{domain1}}}},
		{"ordered domains", dPathTestSegment(domain2, domain1), []DPathSegment{{Domains: []DPathDomain{domain2, domain1}}}},
		{"ordered segments", append(dPathTestSegment(domain2), dPathTestSegment(domain1)...), []DPathSegment{{Domains: []DPathDomain{domain2}}, {Domains: []DPathDomain{domain1}}}},
		{"unknown safi and maximum administrators", dPathTestSegment(unknown), []DPathSegment{{Domains: []DPathDomain{unknown}}}},
		{"zero fields", dPathTestSegment(DPathDomain{}), []DPathSegment{{Domains: []DPathDomain{{}}}}},
		{"maximum domain count", dPathTestSegment(maximum...), []DPathSegment{{Domains: maximum}}},
		{"maximum segment followed by another", append(dPathTestSegment(maximum...), dPathTestSegment(domain1)...), []DPathSegment{{Domains: maximum}, {Domains: []DPathDomain{domain1}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalDPath(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Segments, tt.want) {
				t.Fatalf("segments = %+v, want %+v", got.Segments, tt.want)
			}
			clear(tt.input)
			if !reflect.DeepEqual(got.Segments, tt.want) {
				t.Fatal("decoded domains alias the input")
			}
		})
	}
}

func TestUnmarshalDPathMalformed(t *testing.T) {
	valid := dPathTestSegment(DPathDomain{GlobalAdmin: 65000, LocalAdmin: 1, ISFSAFIType: 70})
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"zero count", make([]byte, 8), "domain count is zero"},
		{"truncated domain", append([]byte{2}, valid[1:]...), "need 15 bytes, got 8"},
		{"maximum count truncated", append([]byte{255}, valid[1:]...), "need 1786 bytes, got 8"},
		{"zero count after segment", append(append([]byte{}, valid...), make([]byte, 8)...), "offset 8: domain count is zero"},
	}
	for n := 0; n < 8; n++ {
		tests = append(tests, struct {
			name  string
			input []byte
			want  string
		}{fmt.Sprintf("length %d", n), valid[:n], "need at least 8 bytes"})
	}
	for n := 1; n < 8; n++ {
		tests = append(tests, struct {
			name  string
			input []byte
			want  string
		}{fmt.Sprintf("trailing %d", n), append(append([]byte{}, valid...), valid[:n]...), fmt.Sprintf("offset 8: need at least 8 bytes, got %d", n)})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalDPath(tt.input)
			if err == nil || !strings.Contains(err.Error(), tt.want) || got != nil {
				t.Fatalf("UnmarshalDPath() = %+v, %v; want nil, error containing %q", got, err, tt.want)
			}
		})
	}
}

func TestDPathBaseAttributes(t *testing.T) {
	first := dPathTestSegment(DPathDomain{GlobalAdmin: 65000, LocalAdmin: 10, ISFSAFIType: 70})
	second := dPathTestSegment(DPathDomain{GlobalAdmin: 65001, LocalAdmin: 20, ISFSAFIType: 128})
	tests := []struct {
		name      string
		values    [][]byte
		malformed bool
	}{
		{"absent", nil, false},
		{"valid", [][]byte{first}, false},
		{"malformed", [][]byte{{1}}, true},
		{"duplicate valid first", [][]byte{first, second}, false},
		{"duplicate malformed first", [][]byte{{1}, first}, true},
		{"duplicate empty first", [][]byte{nil, first}, true},
		{"duplicate malformed second", [][]byte{first, {0}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := []byte{0x40, 1, 1, 0}
			for _, value := range tt.values {
				wire = append(wire, 0xc0, 36, byte(len(value)))
				wire = append(wire, value...)
			}
			got, err := UnmarshalBGPBaseAttributes(wire)
			if err != nil {
				t.Fatal(err)
			}
			if got.Origin != "igp" || got.DPathMalformed != tt.malformed {
				t.Fatalf("origin = %q, malformed = %v; want igp, %v", got.Origin, got.DPathMalformed, tt.malformed)
			}
			if len(tt.values) > 0 && !bytes.Equal(got.DPathAttr, tt.values[0]) {
				t.Fatalf("raw D-PATH = %x, want %x", got.DPathAttr, tt.values[0])
			}
			if len(tt.values) == 0 || tt.malformed {
				if got.DPath != nil {
					t.Fatalf("unexpected decoded D-PATH: %+v", got.DPath)
				}
			} else if got.DPath == nil || got.DPath.Segments[0].Domains[0] != (DPathDomain{GlobalAdmin: 65000, LocalAdmin: 10, ISFSAFIType: 70}) {
				t.Fatalf("decoded D-PATH = %+v", got.DPath)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var decoded BaseAttributes
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if equal, diff := got.Equal(&decoded); !equal {
				t.Fatalf("JSON round-trip changed attributes: %v", diff)
			}
			if len(tt.values) == 0 && bytes.Contains(encoded, []byte("d_path")) {
				t.Fatalf("absent D-PATH appears in JSON: %s", encoded)
			}
		})
	}
}

func TestDPathExtendedLengthAttribute(t *testing.T) {
	domains := make([]DPathDomain, 255)
	for i := range domains {
		domains[i] = DPathDomain{GlobalAdmin: 65000 + uint32(i), LocalAdmin: uint16(i), ISFSAFIType: 128}
	}
	last := DPathDomain{GlobalAdmin: 4200000000, LocalAdmin: 65535, ISFSAFIType: 70}
	value := append(dPathTestSegment(domains...), dPathTestSegment(last)...)
	// RFC 4271 Section 4.3: Extended Length selects a two-octet attribute length.
	attrs := make([]byte, 4, 4+len(value))
	attrs[0], attrs[1] = 0xd0, 36
	binary.BigEndian.PutUint16(attrs[2:4], uint16(len(value)))
	attrs = append(attrs, value...)
	base, err := UnmarshalBGPBaseAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	updateWire := make([]byte, 4, 4+len(attrs))
	binary.BigEndian.PutUint16(updateWire[2:4], uint16(len(attrs)))
	updateWire = append(updateWire, attrs...)
	update, err := UnmarshalBGPUpdate(updateWire)
	if err != nil {
		t.Fatal(err)
	}
	want := &DPath{Segments: []DPathSegment{{Domains: domains}, {Domains: []DPathDomain{last}}}}
	for name, got := range map[string]*BaseAttributes{"base attributes": base, "update": update.BaseAttributes} {
		t.Run(name, func(t *testing.T) {
			if got.DPathMalformed || !reflect.DeepEqual(got.DPath, want) || !bytes.Equal(got.DPathAttr, value) {
				t.Fatalf("D-PATH = %+v, malformed = %v, raw length = %d; want %+v, false, %d", got.DPath, got.DPathMalformed, len(got.DPathAttr), want, len(value))
			}
		})
	}
	if len(update.PathAttributes) != 1 || update.PathAttributes[0].AttributeLength != uint16(len(value)) || update.PathAttributes[0].AttributeTypeFlags != 0xd0 {
		t.Fatalf("extended-length framing lost: %+v", update.PathAttributes)
	}
}

func TestDPathBaseAttributesRawOwnership(t *testing.T) {
	value := dPathTestSegment(DPathDomain{GlobalAdmin: 65000, LocalAdmin: 10, ISFSAFIType: 70})
	got, err := unmarshalBaseAttrsFromSlice([]PathAttribute{{AttributeType: 36, Attribute: value}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{}, value...)
	clear(value)
	if !bytes.Equal(got.DPathAttr, want) {
		t.Fatal("raw D-PATH aliases attribute input")
	}
}

func TestDPathBaseAttributesEqual(t *testing.T) {
	d1 := DPathDomain{GlobalAdmin: 65000, LocalAdmin: 1, ISFSAFIType: 70}
	d2 := DPathDomain{GlobalAdmin: 65001, LocalAdmin: 2, ISFSAFIType: 128}
	tests := []struct {
		name string
		a, b BaseAttributes
	}{
		{"raw", BaseAttributes{DPathAttr: []byte{1}}, BaseAttributes{DPathAttr: []byte{2}}},
		{"malformed", BaseAttributes{DPathMalformed: true}, BaseAttributes{}},
		{"decoded presence", BaseAttributes{DPath: &DPath{}}, BaseAttributes{}},
		{"domain order", BaseAttributes{DPath: &DPath{Segments: []DPathSegment{{Domains: []DPathDomain{d1, d2}}}}}, BaseAttributes{DPath: &DPath{Segments: []DPathSegment{{Domains: []DPathDomain{d2, d1}}}}}},
		{"segment order", BaseAttributes{DPath: &DPath{Segments: []DPathSegment{{Domains: []DPathDomain{d1}}, {Domains: []DPathDomain{d2}}}}}, BaseAttributes{DPath: &DPath{Segments: []DPathSegment{{Domains: []DPathDomain{d2}}, {Domains: []DPathDomain{d1}}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if equal, diff := tt.a.Equal(&tt.a); !equal {
				t.Fatalf("self unequal: %v", diff)
			}
			if equal, diff := tt.a.Equal(&tt.b); equal || !reflect.DeepEqual(diff, []string{"d_path mismatch"}) {
				t.Fatalf("Equal() = %v, %v", equal, diff)
			}
			if equal, _ := tt.b.Equal(&tt.a); equal {
				t.Fatal("reverse comparison unexpectedly equal")
			}
		})
	}
}

func FuzzUnmarshalDPath(f *testing.F) {
	f.Add(dPathTestSegment(DPathDomain{GlobalAdmin: 65000, LocalAdmin: 1, ISFSAFIType: 70}))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := UnmarshalDPath(input)
		if err != nil {
			return
		}
		var encoded []byte
		for _, segment := range decoded.Segments {
			encoded = append(encoded, dPathTestSegment(segment.Domains...)...)
		}
		if !bytes.Equal(encoded, input) {
			t.Fatalf("decode changed D-PATH: got %x, want %x", encoded, input)
		}
	})
}
