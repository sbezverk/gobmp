package srv6

import (
	"net"
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalSRv6L2Service(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *L2Service
	}{
		{
			name: "SRv6 L2 Service with SID Information and SID Structure",
			// Reserved(1) + Sub-TLV type 1 (Information) length 0x001e + value
			input: []byte{
				0x00,                                                                                                             // Reserved
				0x01, 0x00, 0x1e,                                                                                                 // Sub-TLV: type=1, length=30
				0x00,                                                                                                             // Reserved
				0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SID (16 bytes)
				0x00,       // Flags
				0x00, 0x13, // Endpoint Behavior = 19
				0x00,                   // Sub-Sub-TLV reserved
				0x01, 0x00, 0x06,       // Sub-Sub-TLV: type=1 (SID Structure), length=6
				0x28, 0x18, 0x10, 0x00, 0x10, 0x40, // SID Structure values
			},
			expect: &L2Service{
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
		{
			name: "SRv6 L2 Service with SID Information only (no Sub-Sub-TLVs)",
			// Reserved(1) + Sub-TLV type 1 (Information) length 0x0014 + value (no sub-sub-TLVs)
			input: []byte{
				0x00,                                                                                                             // Reserved
				0x01, 0x00, 0x14,                                                                                                 // Sub-TLV: type=1, length=20
				0x00,                                                                                                             // Reserved
				0xfd, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SID (16 bytes)
				0x00,       // Flags
				0x00, 0x06, // Endpoint Behavior = 6 (End)
			},
			expect: &L2Service{
				SubTLVs: map[uint8][]SvcSubTLV{
					1: {
						&InformationSubTLV{
							SID:              net.IP([]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}).To16().String(),
							Flags:            0,
							EndpointBehavior: 6,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRv6L2Service(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Errorf("Mismatches: %+v", deep.Equal(tt.expect, got))
				t.Fatalf("test failed as expected l2 service %+v does not match actual %+v", tt.expect, got)
			}
		})
	}
}
