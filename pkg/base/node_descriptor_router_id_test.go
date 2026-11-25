package base

import (
	"bytes"
	"testing"
)

func TestNodeDescriptorLocalRouterIDs(t *testing.T) {
	tests := []struct {
		name   string
		nd     *NodeDescriptor
		wantV4 []byte
		wantV6 []byte
	}{
		{
			name: "both valid",
			nd: &NodeDescriptor{SubTLV: map[uint16]TLV{
				1028: {Type: 1028, Value: []byte{192, 0, 2, 1}},
				1029: {Type: 1029, Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
			}},
			wantV4: []byte{192, 0, 2, 1},
			wantV6: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name: "wrong lengths are rejected",
			nd: &NodeDescriptor{SubTLV: map[uint16]TLV{
				1028: {Type: 1028, Value: []byte{192, 0, 2}},
				1029: {Type: 1029, Value: []byte{0x20, 0x01}},
			}},
		},
		{name: "missing descriptor", nd: &NodeDescriptor{}},
		{name: "nil descriptor", nd: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.nd.GetLocalNodeIPv4RouterID(); !bytes.Equal(got, tt.wantV4) {
				t.Errorf("GetLocalNodeIPv4RouterID() = %x, want %x", got, tt.wantV4)
			}
			if got := tt.nd.GetLocalNodeIPv6RouterID(); !bytes.Equal(got, tt.wantV6) {
				t.Errorf("GetLocalNodeIPv6RouterID() = %x, want %x", got, tt.wantV6)
			}
		})
	}
}
