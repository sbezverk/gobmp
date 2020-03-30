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
		//		{
		//			name:   "Empty, no attribute AS_PATH",
		//			update: &Update{},
		//			expect: []uint16{},
		//		},
		{
			name: "single segment path 1 AS",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 2,
						Attribute:     []byte{1, 1, 0x2, 0x41},
					},
				},
			},
			expect: []uint16{577},
		},
		{
			name: "single segment path 2 AS",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 2,
						Attribute:     []byte{1, 2, 0x2, 0x41, 0x2, 0x42},
					},
				},
			},
			expect: []uint16{577, 578},
		},
		{
			name: "2 segment path 2 AS",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 2,
						Attribute:     []byte{1, 1, 0x2, 0x41, 1, 1, 0x2, 0x42},
					},
				},
			},
			expect: []uint16{577, 578},
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
