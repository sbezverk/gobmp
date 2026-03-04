package base

import (
	"reflect"
	"testing"
)

func TestLinkNLRIAccessors(t *testing.T) {
	local := &NodeDescriptor{SubTLV: map[uint16]TLV{
		512: {Type: 512, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x0a}}, // ASN=10
		513: {Type: 513, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x01}}, // LSID=1
		514: {Type: 514, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x05}}, // OSPF=5
		515: {Type: 515, Length: 4, Value: []byte{10, 0, 0, 1}},            // IGP=10.0.0.1
	}}
	remote := &NodeDescriptor{SubTLV: map[uint16]TLV{
		512: {Type: 512, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x14}}, // ASN=20
		515: {Type: 515, Length: 4, Value: []byte{10, 0, 0, 2}},            // IGP=10.0.0.2
	}}
	linkD := &LinkDescriptor{LinkTLV: map[uint16]TLV{
		258: {Type: 258, Length: 8, Value: []byte{0, 0, 0, 1, 0, 0, 0, 2}},
		259: {Type: 259, Length: 4, Value: []byte{10, 0, 103, 1}},
		260: {Type: 260, Length: 4, Value: []byte{10, 0, 103, 2}},
	}}
	l := &LinkNLRI{
		ProtocolID: OSPFv2, // 3
		Identifier: [8]byte{0, 0, 0, 0, 0, 0, 0, 7},
		LocalNode:  local,
		RemoteNode: remote,
		Link:       linkD,
	}

	if got := l.GetLinkProtocolID(); got != "OSPFv2" {
		t.Errorf("GetLinkProtocolID() = %q, want \"OSPFv2\"", got)
	}
	if got := l.GetIdentifier(); got != 7 {
		t.Errorf("GetIdentifier() = %d, want 7", got)
	}
	if got := l.GetLocalASN(); got != 10 {
		t.Errorf("GetLocalASN() = %d, want 10", got)
	}
	if got := l.GetRemoteASN(); got != 20 {
		t.Errorf("GetRemoteASN() = %d, want 20", got)
	}
	if got := l.GetLinkASN(true); got != 10 {
		t.Errorf("GetLinkASN(local) = %d, want 10", got)
	}
	if got := l.GetLinkASN(false); got != 20 {
		t.Errorf("GetLinkASN(remote) = %d, want 20", got)
	}
	if got := l.GetLinkLSID(true); got != 1 {
		t.Errorf("GetLinkLSID(local) = %d, want 1", got)
	}
	if got := l.GetLinkLSID(false); got != 0 {
		t.Errorf("GetLinkLSID(remote) = %d, want 0", got)
	}
	if got := l.GetLinkOSPFAreaID(true); got != "5" {
		t.Errorf("GetLinkOSPFAreaID(local) = %q", got)
	}
	if got := l.GetLinkOSPFAreaID(false); got != "" {
		t.Errorf("GetLinkOSPFAreaID(remote) = %q", got)
	}
	if got := l.GetLocalIGPRouterID(); got != "10.0.0.1" {
		t.Errorf("GetLocalIGPRouterID() = %q, want \"10.0.0.1\"", got)
	}
	if got := l.GetRemoteIGPRouterID(); got != "10.0.0.2" {
		t.Errorf("GetRemoteIGPRouterID() = %q, want \"10.0.0.2\"", got)
	}
	ids, err := l.GetLinkID()
	if err != nil || ids[0] != 1 || ids[1] != 2 {
		t.Errorf("GetLinkID() = %v %v", ids, err)
	}
	if addr := l.GetLinkInterfaceAddr(); addr == nil {
		t.Error("GetLinkInterfaceAddr() returned nil")
	}
	if addr := l.GetLinkNeighborAddr(); addr == nil {
		t.Error("GetLinkNeighborAddr() returned nil")
	}
}

func TestUnmarshalLinkNLRI(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		expect  *LinkNLRI
		wantErr bool
	}{
		{
			name:    "link nlri empty",
			input:   []byte{},
			expect:  nil,
			wantErr: true,
		},
		{
			name:    "link nlri malformed",
			input:   []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expect:  nil,
			wantErr: true,
		},
		{
			name:  "link nlri 1",
			input: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x91, 0x01, 0x01, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0x01, 0x03, 0x00, 0x04, 0x09, 0x00, 0x67, 0x01, 0x01, 0x04, 0x00, 0x04, 0x09, 0x00, 0x67, 0x02},
			expect: &LinkNLRI{
				ProtocolID: 2,
				Identifier: [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				LocalNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						512: {
							Type:   512,
							Length: 4,
							Value:  []byte{0, 0, 19, 206},
						},
						513: {
							Type:   513,
							Length: 4,
							Value:  []byte{0, 0, 0, 0},
						},
						515: {
							Type:   515,
							Length: 6,
							Value:  []byte{0, 0, 0, 0, 0, 145},
						},
					},
				},
				RemoteNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						512: {
							Type:   512,
							Length: 4,
							Value:  []byte{0, 0, 19, 206},
						},
						513: {
							Type:   513,
							Length: 4,
							Value:  []byte{0, 0, 0, 0},
						},
						515: {
							Type:   515,
							Length: 6,
							Value:  []byte{0, 0, 0, 0, 0, 147},
						},
					},
				},
				Link: &LinkDescriptor{
					LinkTLV: map[uint16]TLV{
						259: {
							Type:   259,
							Length: 4,
							Value:  []byte{9, 0, 103, 1},
						},
						260: {
							Type:   260,
							Length: 4,
							Value:  []byte{9, 0, 103, 2},
						},
					},
				},
				LocalNodeHash:  "d2a11f59bf25ea669861052e2d20255a",
				RemoteNodeHash: "ab9308a91d9dfe49b0f2992eb878764b",
				LinkHash:       "65a0b6cef01433f331b40f4102fb5f73",
				// LocalNodeHash:  "ae68e174edda04ddf80610d2bec9c522",
				// RemoteNodeHash: "b0ca71813b4508962008be1bb3b73d8d",
				// LinkHash:       "65a0b6cef01433f331b40f4102fb5f73",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLinkNLRI(tt.input)
			if err != nil && !tt.wantErr {
				t.Fatalf("test failed with error: %+v", err)
			}
			if err == nil && tt.wantErr {
				t.Fatalf("test failed as expected error did not occur")
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}

		})
	}
}
