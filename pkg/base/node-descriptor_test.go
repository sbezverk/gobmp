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

// TestNodeDescriptorGetIGPRouterID covers RFC 9552 Section 5.2.1.4:
// IGP Router-ID length identifies the node type - 4 (OSPF non-pseudonode),
// 6 (IS-IS non-pseudonode), 7 (IS-IS pseudonode), 8 (OSPF pseudonode) or 16
// (Direct/Static IPv6 address), discriminated on len(tlv.Value). An 8-byte
// value additionally needs the NLRI Protocol-ID: OSPFv2 carries an IPv4
// interface address, OSPFv3 a 32-bit interface identifier.
func TestNodeDescriptorGetIGPRouterID(t *testing.T) {
	tests := []struct {
		name  string
		nd    *NodeDescriptor
		proto ProtoID
		want  string
	}{
		{
			name: "4-byte OSPF non-pseudonode router-ID",
			nd:   makeNodeDesc(map[uint16]TLV{515: {Type: 515, Length: 4, Value: []byte{10, 0, 0, 1}}}),
			want: "10.0.0.1",
		},
		{
			name: "6-byte IS-IS non-pseudonode ISO System-ID",
			nd:   makeNodeDesc(map[uint16]TLV{515: {Type: 515, Length: 6, Value: []byte{0x00, 0x00, 0x0c, 0x00, 0x12, 0x34}}}),
			want: "0000.0c00.1234",
		},
		{
			name: "7-byte IS-IS pseudonode (System-ID + PSN)",
			nd:   makeNodeDesc(map[uint16]TLV{515: {Type: 515, Length: 7, Value: []byte{0x00, 0x00, 0x0c, 0x00, 0x12, 0x34, 0x01}}}),
			want: "0000.0c00.1234.01",
		},
		{
			name:  "8-byte OSPFv2 pseudonode (DR router-ID + DR interface IPv4 address)",
			nd:    makeNodeDesc(map[uint16]TLV{515: {Type: 515, Length: 8, Value: []byte{10, 0, 0, 1, 192, 168, 1, 1}}}),
			proto: OSPFv2,
			want:  "10.0.0.1:192.168.1.1",
		},
		{
			name:  "8-byte OSPFv3 pseudonode (DR router-ID + DR interface identifier)",
			nd:    makeNodeDesc(map[uint16]TLV{515: {Type: 515, Length: 8, Value: []byte{10, 0, 0, 1, 0, 0, 0x01, 0x02}}}),
			proto: OSPFv3,
			want:  "10.0.0.1:258",
		},
		{
			name:  "mismatched-proxy: OSPFv3 interface identifier that looks like an IPv4 address",
			nd:    makeNodeDesc(map[uint16]TLV{515: {Type: 515, Length: 8, Value: []byte{10, 0, 0, 1, 192, 168, 1, 1}}}),
			proto: OSPFv3,
			want:  "10.0.0.1:3232235777",
		},
		{
			name: "8-byte value without Protocol-ID keeps raw hex",
			nd:   makeNodeDesc(map[uint16]TLV{515: {Type: 515, Length: 8, Value: []byte{10, 0, 0, 1, 192, 168, 1, 1}}}),
			want: "0a00.0001.c0a8.0101",
		},
		{
			name:  "mismatched-proxy: tlv.Length says 4 but Value is 8 bytes (OSPFv2 pseudonode)",
			nd:    makeNodeDesc(map[uint16]TLV{515: {Type: 515, Length: 4, Value: []byte{10, 0, 0, 1, 192, 168, 1, 1}}}),
			proto: OSPFv2,
			want:  "10.0.0.1:192.168.1.1",
		},
		{
			name: "16-byte Direct/Static IPv6 address",
			nd: makeNodeDesc(map[uint16]TLV{515: {Type: 515, Length: 16, Value: []byte{
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}}),
			want: "2001:db8::1",
		},
		{
			name: "TLV absent",
			nd:   makeNodeDesc(nil),
			want: "",
		},
		{
			name: "undefined length keeps raw hex",
			nd:   makeNodeDesc(map[uint16]TLV{515: {Type: 515, Length: 5, Value: []byte{1, 2, 3, 4, 5}}}),
			want: "0102.0304.05",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.nd.GetIGPRouterIDWithProtocol(tt.proto); got != tt.want {
				t.Errorf("GetIGPRouterIDWithProtocol(%d) = %q, want %q", tt.proto, got, tt.want)
			}
		})
	}
}

// TestNodeNLRIGetIGPRouterIDProtocol decodes wire-format Node NLRIs so the
// Protocol-ID byte, not a test-supplied value, selects the 8-byte rendering.
func TestNodeNLRIGetIGPRouterIDProtocol(t *testing.T) {
	tests := []struct {
		name  string
		proto ProtoID
		want  string
	}{
		{name: "OSPFv2 pseudonode", proto: OSPFv2, want: "10.0.0.1:192.168.1.1"},
		{name: "OSPFv3 pseudonode", proto: OSPFv3, want: "10.0.0.1:3232235777"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := []byte{
				byte(tt.proto),
				0, 0, 0, 0, 0, 0, 0, 0, // Identifier
				0x01, 0x00, 0x00, 0x0c, // Local Node Descriptors, length 12
				0x02, 0x03, 0x00, 0x08, // IGP Router-ID TLV 515, length 8
				10, 0, 0, 1, 192, 168, 1, 1,
			}
			n, err := UnmarshalNodeNLRI(b)
			if err != nil {
				t.Fatalf("UnmarshalNodeNLRI() error = %v", err)
			}
			if got := n.GetNodeIGPRouterID(); got != tt.want {
				t.Errorf("GetNodeIGPRouterID() = %q, want %q", got, tt.want)
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
