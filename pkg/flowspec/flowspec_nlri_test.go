package flowspec

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalFlowspecNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *NLRI
		fail   bool
	}{
		{
			name:  "Type 2 (Source Prefix)",
			input: []byte{0x05, 0x02, 0x18, 0x0A, 0x00, 0x07},
			expect: &NLRI{
				Length: 5,
				Spec: []Spec{
					&PrefixSpec{
						SpecType:     2,
						PrefixLength: 24,
						Prefix:       []byte{0x0A, 0x00, 0x07},
					},
				},
			},
			fail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalFlowspecNLRI(tt.input)
			if err != nil && !tt.fail {
				t.Fatalf("failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Logf("Diffs: %+v", deep.Equal(tt.expect, got))
				t.Fatalf("expected NLRI %+v does not match marshaled NLRI: %+v", tt.expect, got)
			}
		})
	}
}
