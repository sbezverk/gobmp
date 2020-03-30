package bgp

import (
	"reflect"
	"testing"
)

func TestGetAttrASPath(t *testing.T) {
	tests := []struct {
		name   string
		update *Update
		expect []uint16
	}{
		{
			name:   "Empty, no attribute AS_PATH",
			update: &Update{},
			expect: []uint16{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.update.GetAttrASPath()
			if !reflect.DeepEqual(tt.expect, got) {
				t.Errorf("Expect list of ASes %+v does not match received list %+v", tt.expect, got)
			}
		})
	}
}
