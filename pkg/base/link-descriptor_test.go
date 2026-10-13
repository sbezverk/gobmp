package base

import (
	"net"
	"testing"
)

func makeLinkDesc(tlvs map[uint16]TLV) *LinkDescriptor {
	return &LinkDescriptor{LinkTLV: tlvs}
}

// TestUnmarshalLinkDescriptorRepeatedAFLinkTLV covers RFC 9815 Section
// 5.2.2.1: an unnumbered link may carry separate Address Family Link
// Descriptor TLVs (1185) for IPv4 and IPv6. Other repeated types still fail.
func TestUnmarshalLinkDescriptorRepeatedAFLinkTLV(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantAF  []byte
		wantErr bool
	}{
		{
			name:   "IPv4 and IPv6 AF link descriptors",
			b:      []byte{0x04, 0xa1, 0x00, 0x01, 0x01, 0x04, 0xa1, 0x00, 0x01, 0x02},
			wantAF: []byte{1, 2},
		},
		{
			name: "single AF link descriptor with link IDs",
			b: []byte{
				0x01, 0x02, 0x00, 0x08, 0, 0, 0, 1, 0, 0, 0, 2,
				0x04, 0xa1, 0x00, 0x01, 0x02,
			},
			wantAF: []byte{2},
		},
		{
			name:   "no AF link descriptor",
			b:      []byte{0x01, 0x02, 0x00, 0x08, 0, 0, 0, 1, 0, 0, 0, 2},
			wantAF: nil,
		},
		{
			name: "repeated link IDs TLV is still rejected",
			b: []byte{
				0x01, 0x02, 0x00, 0x08, 0, 0, 0, 1, 0, 0, 0, 2,
				0x01, 0x02, 0x00, 0x08, 0, 0, 0, 3, 0, 0, 0, 4,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ld, err := UnmarshalLinkDescriptor(tt.b)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalLinkDescriptor() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			got := ld.GetAFLinkTLVs()
			if len(got) != len(tt.wantAF) {
				t.Fatalf("GetAFLinkTLVs() returned %d TLVs, want %d", len(got), len(tt.wantAF))
			}
			for i, tlv := range got {
				if tlv.Type != AFLinkDescriptorTLV || len(tlv.Value) != 1 || tlv.Value[0] != tt.wantAF[i] {
					t.Errorf("GetAFLinkTLVs()[%d] = %+v, want type %d value %d", i, tlv, AFLinkDescriptorTLV, tt.wantAF[i])
				}
			}
			if len(tt.wantAF) > 0 && ld.LinkTLV[AFLinkDescriptorTLV].Value[0] != tt.wantAF[0] {
				t.Errorf("LinkTLV[1185] = %v, want the first instance %d", ld.LinkTLV[AFLinkDescriptorTLV].Value, tt.wantAF[0])
			}
		})
	}
}

// TestLinkDescriptorGetAFLinkTLVsFallback covers a descriptor built without
// UnmarshalLinkDescriptor, which only has LinkTLV set.
func TestLinkDescriptorGetAFLinkTLVsFallback(t *testing.T) {
	ld := makeLinkDesc(map[uint16]TLV{
		AFLinkDescriptorTLV: {Type: AFLinkDescriptorTLV, Length: 1, Value: []byte{1}},
	})
	got := ld.GetAFLinkTLVs()
	if len(got) != 1 || got[0].Value[0] != 1 {
		t.Errorf("GetAFLinkTLVs() = %+v, want the LinkTLV[1185] instance", got)
	}
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
				t.Error("GetLinkMTID() returned nil, want non-nil")
				return
			}
			if got.MTID != tt.wantMTID {
				t.Errorf("MTID = 0x%04x, want 0x%04x", got.MTID, tt.wantMTID)
			}
		})
	}
}
