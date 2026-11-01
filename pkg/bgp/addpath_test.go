package bgp

import (
	"reflect"
	"testing"
)

func TestAddPathModes(t *testing.T) {
	values := [][]byte{
		{0, 1, 1, 1, 0, 2, 1, 2, 0, 1, 4, 3},
		{0, 1, 133, 1, 0, 2, 133, 2, 0, 1, 134, 3, 0, 2, 134, 1},
		{0x12, 0x34, 255, 2, 0x12, 0x35, 255, 1},
		{0, 1, 128, 0, 0, 2, 128, 4, 0, 25, 70, 255},
		{0, 1, 1, 0}, // Ignoring an invalid duplicate must not erase a valid mode.
		{0, 1, 1},    // A truncated tuple must be ignored as a whole.
		{},
	}
	o := &OpenMessage{Capabilities: Capability{69: {nil}}}
	for _, value := range values {
		o.Capabilities[69] = append(o.Capabilities[69], &CapabilityData{Value: value})
	}
	want := map[AFISAFI]uint8{
		{1, 1}: 1, {2, 1}: 2, {1, 4}: 3,
		{1, 133}: 1, {2, 133}: 2, {1, 134}: 3, {2, 134}: 1,
		{0x1234, 255}: 2, {0x1235, 255}: 1,
	}
	if got := o.AddPathModes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("AddPathModes() = %v, want %v", got, want)
	}
	for _, absent := range []*OpenMessage{nil, {}, {Capabilities: Capability{69: {}}}} {
		if got := absent.AddPathModes(); len(got) != 0 {
			t.Errorf("absent ADD-PATH modes = %v, want empty", got)
		}
	}
}
