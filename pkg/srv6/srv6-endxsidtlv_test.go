package srv6

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalSRv6EndXSIDTLV(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *EndXSIDTLV
	}{
		{
			name:  "case 1",
			input: []byte{0x00, 0x06, 0x00, 0x80, 0x00, 0x00, 0x20, 0x01, 0x04, 0x20, 0xFF, 0xFF, 0x10, 0x77, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xE4, 0x00, 0x04, 0x28, 0x18, 0x10, 0x00},
			expect: &EndXSIDTLV{
				EndpointBehavior: 6,
				Flags: &EndXSIDFlags{
					BFlag: false,
					SFlag: false,
					PFlag: false,
				},
				Algorithm: 128,
				SID:       "2001:420:ffff:1077:40::",
				SubTLVs: []SubTLV{&SIDStructure{
					Type:      1252,
					Length:    8,
					LBLength:  40,
					LNLength:  24,
					FunLength: 16,
					ArgLength: 0,
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6EndXSIDTLV(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, result) {
				t.Logf("Differences: %+v", deep.Equal(tt.expect, result))
				t.Fatalf("Expected object: %+v does not match result: %+v", *tt.expect, *result)
			}
		})
	}
}
