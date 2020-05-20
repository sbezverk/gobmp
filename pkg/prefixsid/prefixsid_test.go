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
					SubTLVs: map[uint8][]srv6.SubTLV{
						1: {
							&srv6.InformationSubTLV{
								SID:              net.IP([]byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}).To16().String(),
								Flags:            0,
								EndpointBehavior: 17,
								SubSubTLVs: map[uint8][]srv6.SubSubTLV{
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
