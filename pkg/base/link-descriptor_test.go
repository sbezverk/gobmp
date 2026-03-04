package base

import (
	"net"
	"testing"
)

func makeLinkDesc(tlvs map[uint16]TLV) *LinkDescriptor {
	return &LinkDescriptor{LinkTLV: tlvs}
}

func TestLinkDescriptorGetLinkID(t *testing.T) {
	tests := []struct {
		name       string
		ld         *LinkDescriptor
		wantErr    bool
		wantLocal  uint32
		wantRemote uint32
	}{
		{
			name: "valid local and remote IDs",
			ld: makeLinkDesc(map[uint16]TLV{
				258: {Type: 258, Length: 8, Value: []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02}},
			}),
			wantErr: false, wantLocal: 1, wantRemote: 2,
		},
		{
			name:    "TLV too short",
			ld:      makeLinkDesc(map[uint16]TLV{258: {Type: 258, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x01}}}),
			wantErr: true,
		},
		{
			name:    "TLV absent",
			ld:      makeLinkDesc(nil),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, err := tt.ld.GetLinkID()
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetLinkID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && (ids[0] != tt.wantLocal || ids[1] != tt.wantRemote) {
				t.Errorf("GetLinkID() = %v, want [%d %d]", ids, tt.wantLocal, tt.wantRemote)
			}
		})
	}
}

func TestLinkDescriptorGetLinkIPv4InterfaceAddr(t *testing.T) {
	tests := []struct {
		name    string
		ld      *LinkDescriptor
		wantNil bool
		wantIP  net.IP
	}{
		{
			name:   "TLV present",
			ld:     makeLinkDesc(map[uint16]TLV{259: {Type: 259, Length: 4, Value: []byte{10, 0, 0, 1}}}),
			wantIP: net.IP{10, 0, 0, 1},
		},
		{
			name:    "TLV absent",
			ld:      makeLinkDesc(nil),
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ld.GetLinkIPv4InterfaceAddr()
			if tt.wantNil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if !tt.wantIP.Equal(got) {
				t.Errorf("got %v, want %v", got, tt.wantIP)
			}
		})
	}
}

func TestLinkDescriptorGetLinkIPv4NeighborAddr(t *testing.T) {
	tests := []struct {
		name    string
		ld      *LinkDescriptor
		wantNil bool
		wantIP  net.IP
	}{
		{
			name:   "TLV present",
			ld:     makeLinkDesc(map[uint16]TLV{260: {Type: 260, Length: 4, Value: []byte{10, 0, 0, 2}}}),
			wantIP: net.IP{10, 0, 0, 2},
		},
		{
			name:    "TLV absent",
			ld:      makeLinkDesc(nil),
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ld.GetLinkIPv4NeighborAddr()
			if tt.wantNil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if !tt.wantIP.Equal(got) {
				t.Errorf("got %v, want %v", got, tt.wantIP)
			}
		})
	}
}

func TestLinkDescriptorGetLinkIPv6InterfaceAddr(t *testing.T) {
	v6addr := net.ParseIP("2001:db8::1")
	tests := []struct {
		name    string
		ld      *LinkDescriptor
		wantNil bool
		wantIP  net.IP
	}{
		{
			name:   "TLV present",
			ld:     makeLinkDesc(map[uint16]TLV{261: {Type: 261, Length: 16, Value: []byte(v6addr.To16())}}),
			wantIP: v6addr,
		},
		{
			name:    "TLV absent",
			ld:      makeLinkDesc(nil),
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ld.GetLinkIPv6InterfaceAddr()
			if tt.wantNil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if !tt.wantIP.Equal(got) {
				t.Errorf("got %v, want %v", got, tt.wantIP)
			}
		})
	}
}

func TestLinkDescriptorGetLinkIPv6NeighborAddr(t *testing.T) {
	v6addr := net.ParseIP("2001:db8::2")
	tests := []struct {
		name    string
		ld      *LinkDescriptor
		wantNil bool
		wantIP  net.IP
	}{
		{
			name:   "TLV present",
			ld:     makeLinkDesc(map[uint16]TLV{262: {Type: 262, Length: 16, Value: []byte(v6addr.To16())}}),
			wantIP: v6addr,
		},
		{
			name:    "TLV absent",
			ld:      makeLinkDesc(nil),
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ld.GetLinkIPv6NeighborAddr()
			if tt.wantNil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if !tt.wantIP.Equal(got) {
				t.Errorf("got %v, want %v", got, tt.wantIP)
			}
		})
	}
}

func TestLinkDescriptorGetLinkMTID(t *testing.T) {
	tests := []struct {
		name     string
		ld       *LinkDescriptor
		wantNil  bool
		wantMTID uint16
	}{
		{
			name:     "valid MTID entry",
			ld:       makeLinkDesc(map[uint16]TLV{263: {Type: 263, Length: 2, Value: []byte{0x00, 0x02}}}),
			wantMTID: 0x0002,
		},
		{
			name:    "TLV absent",
			ld:      makeLinkDesc(nil),
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ld.GetLinkMTID()
			if tt.wantNil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("GetLinkMTID() returned nil, want non-nil")
			}
			if got.MTID != tt.wantMTID {
				t.Errorf("MTID = 0x%04x, want 0x%04x", got.MTID, tt.wantMTID)
			}
		})
	}
}
