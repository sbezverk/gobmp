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
		fail   bool
	}{
		{
			name:  "label 1",
			input: []byte{5, 220, 33},
			expect: &Label{
				Value: 24002,
				Exp:   0,
				BoS:   true,
			},
			fail: false,
		},
		{
			name:  "label 2",
			input: []byte{5, 220, 65},
			expect: &Label{
				Value: 24004,
				Exp:   0,
				BoS:   true,
			},
			fail: false,
		},
		{
			name:   "wrong length",
			input:  []byte{5, 220, 33, 0},
			expect: nil,
			fail:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := makeLabel(tt.input)
			if err != nil && !tt.fail {
				t.Fatalf("expected to succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatalf("expected to fail but succeeded")
			}
			if !reflect.DeepEqual(got, tt.expect) {
				t.Errorf("Expected label %+v does not match to actual label %+v", got, *tt.expect)
			}
		})
	}
}
