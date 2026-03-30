package prefixsid

import (
	"net"
	"reflect"
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
