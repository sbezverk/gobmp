package srv6

import (
	"net"
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalInformationSubTLV_ShortTrailingBytes(t *testing.T) {
	// 20-byte valid header (1 reserved + 16 SID + 1 flags + 2 endpoint behavior)
	// followed by 1-3 trailing bytes that are too short for a sub-sub-TLV header
	// (which requires 4 bytes: 1 reserved + 1 type + 2 length).
	// The function must not panic; it should ignore the trailing bytes.
	base := []byte{
		0x00,                                                                                           // reserved
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SID (16 bytes)
		0x00,       // flags
		0x00, 0x06, // endpoint behavior
	}
	for trailing := 1; trailing <= 3; trailing++ {
		input := make([]byte, len(base)+trailing)
		copy(input, base)
		got, err := UnmarshalInformationSubTLV(input)
		if err != nil {
			t.Fatalf("trailing=%d: unexpected error: %v", trailing, err)
		}
		if got.SubSubTLVs != nil {
			t.Fatalf("trailing=%d: expected nil SubSubTLVs, got %v", trailing, got.SubSubTLVs)
		}
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
