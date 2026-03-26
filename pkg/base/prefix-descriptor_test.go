package base

import (
	"testing"
)

func TestPrefixDescriptorGetPrefixMTID(t *testing.T) {
	tests := []struct {
		name      string
		pd        *PrefixDescriptor
		wantNil   bool
		wantMTID  uint16
		wantAFlag bool
	}{
		{
			name:      "TLV present with AFlag",
			pd:        &PrefixDescriptor{PrefixTLV: map[uint16]TLV{263: {Type: 263, Length: 2, Value: []byte{0x40, 0x03}}}},
			wantMTID:  3,
			wantAFlag: true,
		},
		{
			name:    "TLV absent",
			pd:      &PrefixDescriptor{PrefixTLV: map[uint16]TLV{}},
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pd.GetPrefixMTID()
			if tt.wantNil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Error("GetPrefixMTID() returned nil")
				return
			}
			if got.MTID != tt.wantMTID {
				t.Errorf("MTID = %d, want %d", got.MTID, tt.wantMTID)
			}
			if got.AFlag != tt.wantAFlag {
				t.Errorf("AFlag = %v, want %v", got.AFlag, tt.wantAFlag)
			}
		})
	}
}

func TestPrefixDescriptorGetPrefixOSPFRouteType(t *testing.T) {
	tests := []struct {
		name string
		pd   *PrefixDescriptor
		want uint8
	}{
		{
			name: "TLV present",
			pd:   &PrefixDescriptor{PrefixTLV: map[uint16]TLV{264: {Type: 264, Length: 1, Value: []byte{0x03}}}},
			want: 3,
		},
		{
			name: "TLV absent",
			pd:   &PrefixDescriptor{PrefixTLV: map[uint16]TLV{}},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pd.GetPrefixOSPFRouteType(); got != tt.want {
				t.Errorf("GetPrefixOSPFRouteType() = %d, want %d", got, tt.want)
			}
		})
	}
}
