package bgpls

import (
	"reflect"
	"testing"
)

func TestUnmarshalFlexAlgoDefinition(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *FlexAlgoDefinition
	}{
		{
			name:  "Real scenario 1",
			input: []byte{0x80, 0x00, 0x00, 0x80, 0x04, 0x10, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00},
			expect: &FlexAlgoDefinition{
				FlexAlgorithm:   128,
				MetricType:      0,
				Priority:        128,
				CalculationType: 0,
				ExcludeAny:      []uint32{0, 0, 0, 0, 0, 0, 0, 0x80000000},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalFlexAlgoDefinition(tt.input)
			if err != nil {
				t.Errorf("failed to unmarshal flex algo definition with error: %+v", err)
			}
			if !reflect.DeepEqual(result, tt.expect) {
				t.Errorf("expected %+v and resulted %+v flex algo definitions do not match", *tt.expect, *result)
			}
		})
	}
}
