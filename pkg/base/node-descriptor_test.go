package base

import (
	"testing"
)

func makeNodeDesc(subtlvs map[uint16]TLV) *NodeDescriptor {
	return &NodeDescriptor{SubTLV: subtlvs}
}

func TestNodeDescriptorGetASN(t *testing.T) {
	tests := []struct {
		name string
		nd   *NodeDescriptor
		want uint32
	}{
		{
			name: "TLV present",
			nd:   makeNodeDesc(map[uint16]TLV{512: {Type: 512, Length: 4, Value: []byte{0x00, 0x01, 0x86, 0xa0}}}),
			want: 100000,
		},
		{
			name: "TLV absent",
			nd:   makeNodeDesc(nil),
			want: 0,
		},
		{
			name: "TLV present but short value",
			nd:   makeNodeDesc(map[uint16]TLV{512: {Type: 512, Length: 2, Value: []byte{0x00, 0x01}}}),
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.nd.GetASN(); got != tt.want {
				t.Errorf("GetASN() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNodeDescriptorGetLSID(t *testing.T) {
	tests := []struct {
		name string
		nd   *NodeDescriptor
		want uint32
	}{
		{
			name: "TLV present",
			nd:   makeNodeDesc(map[uint16]TLV{513: {Type: 513, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x02}}}),
			want: 2,
		},
		{
			name: "TLV absent",
			nd:   makeNodeDesc(nil),
			want: 0,
		},
		{
			name: "TLV present but short value",
			nd:   makeNodeDesc(map[uint16]TLV{513: {Type: 513, Length: 1, Value: []byte{0x01}}}),
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.nd.GetLSID(); got != tt.want {
				t.Errorf("GetLSID() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNodeDescriptorGetOSPFAreaID(t *testing.T) {
	tests := []struct {
		name string
		nd   *NodeDescriptor
		want string
	}{
		{
			name: "TLV present",
			nd:   makeNodeDesc(map[uint16]TLV{514: {Type: 514, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x07}}}),
			want: "7",
		},
		{
			name: "TLV absent",
			nd:   makeNodeDesc(nil),
			want: "",
		},
		{
			name: "TLV present but short value",
			nd:   makeNodeDesc(map[uint16]TLV{514: {Type: 514, Length: 3, Value: []byte{0x00, 0x00, 0x07}}}),
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.nd.GetOSPFAreaID(); got != tt.want {
				t.Errorf("GetOSPFAreaID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNodeDescriptorGetBGPRouterID(t *testing.T) {
	tests := []struct {
		name    string
		nd      *NodeDescriptor
		wantNil bool
		wantVal []byte
	}{
		{
			name:    "TLV present",
			nd:      makeNodeDesc(map[uint16]TLV{516: {Type: 516, Length: 4, Value: []byte{0x0a, 0x00, 0x00, 0x01}}}),
			wantNil: false,
			wantVal: []byte{0x0a, 0x00, 0x00, 0x01},
		},
		{
			name:    "TLV absent",
			nd:      makeNodeDesc(nil),
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.nd.GetBGPRouterID()
			if tt.wantNil {
				if got != nil {
					t.Errorf("GetBGPRouterID() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.wantVal) || got[3] != tt.wantVal[3] {
				t.Errorf("GetBGPRouterID() = %v, want %v", got, tt.wantVal)
			}
		})
	}
}

func TestNodeDescriptorGetConfedMemberASN(t *testing.T) {
	tests := []struct {
		name string
		nd   *NodeDescriptor
		want uint32
	}{
		{
			name: "TLV present",
			nd:   makeNodeDesc(map[uint16]TLV{517: {Type: 517, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x05}}}),
			want: 5,
		},
		{
			name: "TLV absent",
			nd:   makeNodeDesc(nil),
			want: 0,
		},
		{
			name: "TLV present but short value",
			nd:   makeNodeDesc(map[uint16]TLV{517: {Type: 517, Length: 2, Value: []byte{0x00, 0x05}}}),
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.nd.GetConfedMemberASN(); got != tt.want {
				t.Errorf("GetConfedMemberASN() = %d, want %d", got, tt.want)
			}
		})
	}
}
