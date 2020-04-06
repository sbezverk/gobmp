package l3vpn

import (
	"reflect"
	"testing"
)

func TestMakeLabel(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *Label
	}{
		{
			name:   "label 1",
			input:  []byte{},
			expect: &Label{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := makeLabel(tt.input)
			if !reflect.DeepEqual(&got, tt.expect) {
				t.Errorf("Expected label %+v does not match to actual label %+v", got, *tt.expect)
			}
		})
	}
}
