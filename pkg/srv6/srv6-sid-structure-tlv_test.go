package srv6

import (
	"bytes"
	"testing"
)

// RFC 9514 §8: the SRv6 SID Structure TLV value is four octets.
var sidStructureLengthCases = []struct {
	name    string
	value   []byte
	wantErr bool
}{
	{name: "rejects an empty value", value: []byte{}, wantErr: true},
	{name: "rejects a three octet value", value: []byte{40, 24, 16}, wantErr: true},
	{name: "rejects a five octet value", value: []byte{40, 24, 16, 8, 0}, wantErr: true},
	{name: "decodes a four octet value", value: []byte{40, 24, 16, 8}},
}

func TestUnmarshalSRv6SIDStructureTLVLength(t *testing.T) {
	for _, tc := range sidStructureLengthCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnmarshalSRv6SIDStructureTLV(tc.value)

			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("UnmarshalSRv6SIDStructureTLV(%v) error = %v, want error: %t", tc.value, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			want := SIDStructure{LBLength: 40, LNLength: 24, FunLength: 16, ArgLength: 8}
			if *got != want {
				t.Errorf("UnmarshalSRv6SIDStructureTLV(%v) = %+v, want %+v", tc.value, *got, want)
			}
		})
	}
}

func TestUnmarshalSRv6EndXSIDTLVSIDStructureLength(t *testing.T) {
	for _, tc := range sidStructureLengthCases {
		t.Run(tc.name, func(t *testing.T) {
			// RFC 9514 §4.1: 22 fixed octets followed by the SID Structure sub-TLV.
			wire := append(bytes.Repeat([]byte{0}, EndXSIDTLVMinLen), 0x04, 0xe4, 0, byte(len(tc.value)))
			wire = append(wire, tc.value...)

			got, err := UnmarshalSRv6EndXSIDTLV(wire)

			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("UnmarshalSRv6EndXSIDTLV(%v) error = %v, want error: %t", wire, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			want := SIDStructure{Type: 1252, Length: 8, LBLength: 40, LNLength: 24, FunLength: 16, ArgLength: 8}
			if len(got.SubTLVs) != 1 {
				t.Fatalf("UnmarshalSRv6EndXSIDTLV(%v) sub-TLVs = %d, want 1", wire, len(got.SubTLVs))
			}
			if structure, ok := got.SubTLVs[0].(*SIDStructure); !ok || *structure != want {
				t.Errorf("UnmarshalSRv6EndXSIDTLV(%v) sub-TLV = %+v, want %+v", wire, got.SubTLVs[0], want)
			}
		})
	}
}
