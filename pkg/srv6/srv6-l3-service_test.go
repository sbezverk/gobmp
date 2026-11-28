package srv6

import (
	"fmt"
	"net"
	"reflect"
	"slices"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalInformationSubTLV_TrailingOctets(t *testing.T) {
	// 21 octets are the whole fixed part (RFC 9252 §3.1). One or two more are
	// too short for a Sub-Sub-TLV header (type and 2-octet length).
	tests := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{name: "the fixed part alone is valid", length: 21},
		{name: "one trailing octet is rejected", length: 22, wantErr: true},
		{name: "two trailing octets are rejected", length: 23, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]byte, tt.length)
			got, err := UnmarshalInformationSubTLV(input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalInformationSubTLV(%x) error = %v, want error: %t", input, err, tt.wantErr)
			}
			if err == nil && got.SubSubTLVs != nil {
				t.Errorf("UnmarshalInformationSubTLV(%x) SubSubTLVs = %v, want nil", input, got.SubSubTLVs)
			}
		})
	}
}

func TestUnmarshalSRv6L3ServiceSubSubTLV_LengthPastTheEndIsRejected(t *testing.T) {
	// Spare capacity holds the octets an unchecked slice would borrow.
	wire := []byte{0x00, 0x01, 0x00, 0x06, 40, 24, 16, 0, 16, 64}
	for n := 2; n < len(wire); n++ {
		t.Run(fmt.Sprintf("input cut to %d octets is rejected", n), func(t *testing.T) {
			if got, err := UnmarshalSRv6L3ServiceSubSubTLV(wire[:n]); err == nil {
				t.Errorf("UnmarshalSRv6L3ServiceSubSubTLV(%x) = %v, want an error", wire[:n], got)
			}
		})
	}
}

func TestUnmarshalSRv6L3ServiceSubSubTLV_SIDStructureOfWrongLength(t *testing.T) {
	// RFC 9252 §7: only a length that does not fit the enclosing Sub-TLV makes a
	// Sub-Sub-TLV malformed.
	var (
		reserved   = []byte{0x00}
		empty      = []byte{0x01, 0x00, 0x00}
		short      = []byte{0x01, 0x00, 0x05, 40, 24, 16, 0, 16}
		long       = []byte{0x01, 0x00, 0x07, 40, 24, 16, 0, 16, 64, 0}
		valid      = []byte{0x01, 0x00, 0x06, 40, 24, 16, 0, 16, 64}
		unknown    = []byte{0x02, 0x00, 0x01, 0xaa}
		overrun    = []byte{0x01, 0x00, 0x06, 40}
		shortStart = []byte{0x01, 0x00}
	)
	structure := &SIDStructureSubSubTLV{LocalBlockLength: 40, LocalNodeLength: 24, FunctionLength: 16,
		TranspositionLength: 16, TranspositionOffset: 64}
	onlyStructure := map[uint8][]SvcSubSubTLV{1: {structure}}
	nothing := map[uint8][]SvcSubSubTLV{}
	tests := []struct {
		name    string
		input   []byte
		want    map[uint8][]SvcSubSubTLV
		wantErr bool
	}{
		{name: "leaves out a SID Structure of length zero",
			input: slices.Concat(reserved, empty), want: nothing},
		{name: "leaves out a SID Structure of length five",
			input: slices.Concat(reserved, short), want: nothing},
		{name: "leaves out a SID Structure of length seven",
			input: slices.Concat(reserved, long), want: nothing},
		{name: "decodes a valid SID Structure after an empty one",
			input: slices.Concat(reserved, empty, valid), want: onlyStructure},
		{name: "decodes a valid SID Structure after a short one",
			input: slices.Concat(reserved, short, valid), want: onlyStructure},
		{name: "decodes a valid SID Structure after a long one",
			input: slices.Concat(reserved, long, valid), want: onlyStructure},
		{name: "keeps a valid SID Structure before a long one",
			input: slices.Concat(reserved, valid, long), want: onlyStructure},
		{name: "keeps an unknown Sub-Sub-TLV after a short SID Structure",
			input: slices.Concat(reserved, short, unknown),
			want:  map[uint8][]SvcSubSubTLV{2: {[]byte{0xaa}}}},
		{name: "rejects an overrunning length after a short SID Structure",
			input: slices.Concat(reserved, short, overrun), wantErr: true},
		{name: "rejects a truncated header after a long SID Structure",
			input: slices.Concat(reserved, long, shortStart), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRv6L3ServiceSubSubTLV(tt.input)

			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalSRv6L3ServiceSubSubTLV(%x) error = %v, want error: %t", tt.input, err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalSRv6L3ServiceSubSubTLV(%x) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestUnmarshalSRv6L3Service_EmptyValueIsRejected(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "a nil value is rejected"},
		{name: "a value of length zero is rejected", input: []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := UnmarshalSRv6L3Service(tt.input); err == nil {
				t.Errorf("UnmarshalSRv6L3Service(%#v) = %+v, want an error", tt.input, got)
			}
		})
	}
}

func TestUnmarshalSRv6L3Service(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *L3Service
	}{
		{
			name:  "SRv6 L3 Service 1",
			input: []byte{0x00, 0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
			expect: &L3Service{
				SubTLVs: map[uint8][]SvcSubTLV{
					1: {
						&InformationSubTLV{
							SID:              net.IP([]byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}).To16().String(),
							Flags:            0,
							EndpointBehavior: 19,
							SubSubTLVs: map[uint8][]SvcSubSubTLV{
								1: {
									&SIDStructureSubSubTLV{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRv6L3Service(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Errorf("Mismatches: %+v", deep.Equal(tt.expect, got))
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}

		})
	}
}
