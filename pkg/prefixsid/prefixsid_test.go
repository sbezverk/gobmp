package prefixsid

import (
	"errors"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

func TestUnmarshalBGPAttrPrefixSID(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *PSid
	}{
		{
			name:  "mp unicast nlri 1",
			input: []byte{0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4},
			expect: &PSid{
				LabelIndex: &LabelIndexTLV{
					Type:       1,
					Length:     7,
					LabelIndex: 164,
				},
				OriginatorSRGB: nil,
			},
		},
		{
			name:  "prefix sid type 5",
			input: []byte{0x05, 0x00, 0x22, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
			expect: &PSid{
				SRv6L3Service: &srv6.L3Service{
					SubTLVs: map[uint8][]srv6.SvcSubTLV{
						1: {
							&srv6.InformationSubTLV{
								SID:              net.IP([]byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}).To16().String(),
								Flags:            0,
								EndpointBehavior: 17,
								SubSubTLVs: map[uint8][]srv6.SvcSubSubTLV{
									1: {
										&srv6.SIDStructureSubSubTLV{
											LocalBlockLength:    0x28,
											LocalNodeLength:     0x18,
											FunctionLength:      0x10,
											ArgumentLength:      0,
											TranspositionLength: 0x10,
											TranspositionOffset: 0x40,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "type 3 originator srgb",
			// Type=3, Length=8 (2 Flags + 6 SRGB), Flags=0x0000, First=16000 (0x003E80), Number=8000 (0x001F40)
			input: []byte{0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x3E, 0x80, 0x00, 0x1F, 0x40},
			expect: &PSid{
				OriginatorSRGB: &OriginatorSRGBTLV{
					Type:   3,
					Length: 8,
					Flags:  0,
					SRGB: []SRGB{
						{First: 16000, Number: 8000},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBGPAttrPrefixSID(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Errorf("Diffs: %+v\n", deep.Equal(tt.expect, got))
				t.Fatalf("test failed as expected prefix sid %+v does not match the actual %+v", tt.expect, got)
			}
		})
	}
}

// firstL3ServiceTLV is a valid SRv6 L3 Service TLV (type 5) carrying one
// 21-octet SRv6 SID Information Sub-TLV for 2001:db8::1, behavior 19.
var firstL3ServiceTLV = []byte{
	0x05, 0x00, 0x19, 0x00,
	0x01, 0x00, 0x15, 0x00,
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x13, 0x00,
}

func TestUnmarshalBGPAttrPrefixSIDIgnoresLaterL3ServiceTLVs(t *testing.T) {
	// RFC 9252 §7: all but the first SRv6 L3 Service TLV are ignored.
	labelIndexTLV := []byte{0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4}
	want := &PSid{
		LabelIndex: &LabelIndexTLV{Type: 1, Length: 7, LabelIndex: 164},
		SRv6L3Service: &srv6.L3Service{
			SubTLVs: map[uint8][]srv6.SvcSubTLV{
				1: {&srv6.InformationSubTLV{SID: "2001:db8::1", EndpointBehavior: 19}},
			},
		},
	}
	tests := []struct {
		name     string
		laterTLV []byte
	}{
		{name: "ignores a later empty TLV", laterTLV: []byte{0x05, 0x00, 0x00}},
		{name: "ignores a later malformed TLV", laterTLV: []byte{0x05, 0x00, 0x03, 0x00, 0x01, 0x00}},
		{name: "keeps the first SID when a later TLV is also valid", laterTLV: []byte{
			0x05, 0x00, 0x19, 0x00,
			0x01, 0x00, 0x15, 0x00,
			0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			0x00, 0x00, 0x14, 0x00,
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := slices.Concat(firstL3ServiceTLV, tc.laterTLV, labelIndexTLV)

			got, err := UnmarshalBGPAttrPrefixSID(input)

			if err != nil {
				t.Fatalf("UnmarshalBGPAttrPrefixSID(%x) error = %v, want nil", input, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("UnmarshalBGPAttrPrefixSID(%x) differs from want: %v", input, deep.Equal(got, want))
			}
		})
	}
}

func TestUnmarshalBGPAttrPrefixSIDRejectsBadL3ServiceTLVs(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{
			name:    "rejects a first TLV that runs past the attribute end",
			input:   []byte{0x05, 0x00, 0x04, 0x00},
			wantErr: "SRv6 L3 service value truncated at offset 3: need 4 bytes, have 1",
		},
		{
			name:    "rejects a later TLV that runs past the attribute end",
			input:   slices.Concat(firstL3ServiceTLV, []byte{0x05, 0x00, 0x04, 0x00}),
			wantErr: "SRv6 L3 service value truncated at offset 31: need 4 bytes, have 1",
		},
		{
			name:    "rejects a zero-length first TLV",
			input:   []byte{0x05, 0x00, 0x00},
			wantErr: "SRv6 L3 service TLV at offset 0 has zero length",
		},
		{
			name:    "rejects a first TLV whose Information Sub-TLV is too short",
			input:   []byte{0x05, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00},
			wantErr: "srv6 Information sub-TLV too short",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnmarshalBGPAttrPrefixSID(tc.input)

			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("UnmarshalBGPAttrPrefixSID(%x) error = %v, want it to contain %q", tc.input, err, tc.wantErr)
			}
			if got != nil {
				t.Errorf("UnmarshalBGPAttrPrefixSID(%x) = %+v, want nil", tc.input, got)
			}
		})
	}
}

// RFC 9252 §7 and RFC 8669 §6 call for different error handling, so only a
// malformed SRv6 Service TLV is reported as ErrSRv6ServiceMalformed. A bad
// Label-Index or SRGB length also returns the rest of the attribute, which
// families other than labeled unicast publish (RFC 8669 §3.1, §3.2).
func TestUnmarshalBGPAttrPrefixSIDTellsSRv6ServiceErrorsApart(t *testing.T) {
	l3Only := &PSid{SRv6L3Service: &srv6.L3Service{SubTLVs: map[uint8][]srv6.SvcSubTLV{
		1: {&srv6.InformationSubTLV{SID: "2001:db8::1", EndpointBehavior: 19}},
	}}}
	var (
		labelIndex      = []byte{0x01, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0xa4}
		overrun         = []byte{0x09, 0x00, 0x04}
		shortLabelIndex = []byte{0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0}
		// The eighth value octet is the type of an SRv6 L3 Service TLV.
		longLabelIndex = []byte{0x01, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0x05}
		shortSRGB      = []byte{0x03, 0x00, 0x01, 0}
		badL3          = []byte{0x05, 0x00, 0x00}
		badL2          = []byte{0x06, 0x00, 0x00}
		validL2        = append([]byte{0x06}, firstL3ServiceTLV[1:]...)
	)
	tests := []struct {
		name        string
		input       []byte
		wantService bool // an ErrSRv6ServiceMalformed error
		wantErr     string
		want        *PSid // returned beside the error
	}{
		{name: "a zero-length L2 TLV", input: badL2, wantService: true,
			wantErr: "SRv6 L2 service TLV at offset 0 has zero length"},
		{name: "a zero-length L3 TLV", input: badL3, wantService: true,
			wantErr: "SRv6 L3 service TLV at offset 0 has zero length"},
		{name: "an L3 TLV header of one octet", input: []byte{0x05}, wantService: true, wantErr: "truncated at offset 0"},
		{name: "an L2 TLV header of two octets", input: []byte{0x06, 0x00}, wantService: true, wantErr: "truncated at offset 0"},
		{name: "an L2 TLV running past the attribute end", input: []byte{0x06, 0x00, 0x04, 0x00}, wantService: true,
			wantErr: "SRv6 L2 service value truncated at offset 3: need 4 bytes, have 1"},
		{name: "a later L2 TLV running past the attribute end",
			input: slices.Concat(validL2, []byte{0x06, 0x00, 0x04, 0x00}), wantService: true,
			wantErr: "SRv6 L2 service value truncated at offset 31"},
		{name: "an L2 TLV with a short Information Sub-TLV",
			input: []byte{0x06, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00}, wantService: true,
			wantErr: "srv6 Information sub-TLV too short"},
		{name: "a malformed L2 TLV after a valid L3 TLV", input: slices.Concat(firstL3ServiceTLV, badL2),
			wantService: true, wantErr: "L2 service"},
		{name: "a malformed L3 TLV after a valid L2 TLV", input: slices.Concat(validL2, badL3),
			wantService: true, wantErr: "L3 service"},
		{name: "a Label-Index of length six", input: shortLabelIndex, wantErr: "label index TLV length 6",
			want: &PSid{}},
		{name: "a Label-Index of length eight", input: longLabelIndex, wantErr: "label index TLV length 8",
			want: &PSid{}},
		{name: "an Originator SRGB of length one", input: shortSRGB, wantErr: "originator SRGB length too short",
			want: &PSid{}},
		{name: "a Label-Index of length six before a valid L3 TLV",
			input: slices.Concat(shortLabelIndex, firstL3ServiceTLV), wantErr: "label index TLV length 6", want: l3Only},
		{name: "a short Originator SRGB after a Label-Index", input: slices.Concat(labelIndex, shortSRGB),
			wantErr: "originator SRGB length too short",
			want:    &PSid{LabelIndex: &LabelIndexTLV{Type: 1, Length: 7, LabelIndex: 164}}},
		{name: "each of two bad TLVs", input: slices.Concat(shortLabelIndex, shortSRGB),
			wantErr: "length 6, want 7\nprefix SID originator SRGB length too short", want: &PSid{}},
		{name: "a TLV running past the end after a Label-Index of length six",
			input: slices.Concat(shortLabelIndex, overrun), wantErr: "unknown TLV value truncated"},
		{name: "a malformed L3 TLV after a Label-Index of length six",
			input: slices.Concat(shortLabelIndex, badL3), wantService: true, wantErr: "L3 service"},
		{name: "a malformed L2 TLV after a Label-Index of length eight",
			input: slices.Concat(longLabelIndex, badL2), wantService: true, wantErr: "L2 service"},
		{name: "a malformed L3 TLV after an Originator SRGB of length one",
			input: slices.Concat(shortSRGB, badL3), wantService: true, wantErr: "L3 service"},
		{name: "a Label-Index running past the attribute end", input: []byte{0x01, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0},
			wantErr: "label index TLV truncated"},
		{name: "an Originator SRGB running past the attribute end", input: []byte{0x03, 0x00, 0x08, 0, 0},
			wantErr: "originator SRGB value truncated"},
		{name: "a truncated header of another type", input: []byte{0x07, 0x00}, wantErr: "truncated at offset 0"},
	}

	for _, tc := range tests {
		t.Run(tc.name+" is reported", func(t *testing.T) {
			got, err := UnmarshalBGPAttrPrefixSID(tc.input)

			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("UnmarshalBGPAttrPrefixSID(%x) error = %v, want it to contain %q", tc.input, err, tc.wantErr)
			}
			if isService := errors.Is(err, ErrSRv6ServiceMalformed); isService != tc.wantService {
				t.Errorf("errors.Is(%v, ErrSRv6ServiceMalformed) = %t, want %t", err, isService, tc.wantService)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("UnmarshalBGPAttrPrefixSID(%x) = %+v, want %+v", tc.input, got, tc.want)
			}
		})
	}
}

// RFC 9252 §7: the L2 Service TLV is validated, its content is not published, and
// all but the first one are ignored.
func TestUnmarshalBGPAttrPrefixSIDLeavesOutL2ServiceContent(t *testing.T) {
	validL2 := append([]byte{0x06}, firstL3ServiceTLV[1:]...)
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "a valid L2 TLV is left out", input: validL2},
		{name: "an L2 TLV of length one is left out", input: []byte{0x06, 0x00, 0x01, 0x00}},
		{name: "a later empty L2 TLV is ignored", input: slices.Concat(validL2, []byte{0x06, 0x00, 0x00})},
		{name: "a later L2 TLV with a malformed Sub-TLV is ignored",
			input: slices.Concat(validL2, []byte{0x06, 0x00, 0x03, 0x00, 0x01, 0x00})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnmarshalBGPAttrPrefixSID(tc.input)

			if err != nil {
				t.Fatalf("UnmarshalBGPAttrPrefixSID(%x) error = %v, want nil", tc.input, err)
			}
			if !got.IsEmpty() {
				t.Errorf("UnmarshalBGPAttrPrefixSID(%x) = %+v, want an empty PSid", tc.input, got)
			}
		})
	}
}

func TestUnmarshalBGPAttrPrefixSID_Bounds(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "truncated header", input: []byte{0x01, 0x00}},
		{name: "type 1 truncated value", input: []byte{0x01, 0x00, 0x07, 0x00, 0x00}},
		// Type 3: need 3+ bytes to enter switch, then p++ leaves insufficient for 4-byte read
		{name: "type 3 truncated header", input: []byte{0x03, 0x00, 0x04}},
		// Type 3: valid header but SRGB Length < 2
		{name: "type 3 length too short", input: []byte{0x03, 0x00, 0x01, 0x00, 0x00}},
		// Type 3: Length=8 implies 1 SRGB entry (6 bytes) but buffer too short
		{name: "type 3 truncated srgb value", input: []byte{0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}},
		// Type 5: zero-length value triggers SRv6 L3 Service guard
		{name: "type 5 zero length", input: []byte{0x05, 0x00, 0x00}},
		// Type 5: valid length header but value truncated
		{name: "type 5 truncated value", input: []byte{0x05, 0x00, 0x10, 0x00}},
		// Unknown type: valid length but value truncated
		{name: "unknown type truncated value", input: []byte{0xFF, 0x00, 0x08, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalBGPAttrPrefixSID(tt.input)
			if err == nil {
				t.Fatal("expected error for truncated input")
			}
		})
	}
}
