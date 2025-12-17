package bgpls

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalRangeTLV_ISIS(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		proto     base.ProtoID
		wantFlags byte
		wantSize  uint16
		wantErr   bool
	}{
		{
			name: "IS-IS all flags set",
			input: []byte{
				0xF8,       // Flags: F|M|S|D|A = 11111000
				0x00,       // Reserved
				0x00, 0x0A, // Range Size = 10
			},
			proto:     base.ISISL2,
			wantFlags: 0xF8,
			wantSize:  10,
			wantErr:   false,
		},
		{
			name: "IS-IS no flags",
			input: []byte{
				0x00,       // Flags: all clear
				0x00,       // Reserved
				0x00, 0x01, // Range Size = 1
			},
			proto:     base.ISISL2,
			wantFlags: 0x00,
			wantSize:  1,
			wantErr:   false,
		},
		{
			name: "IS-IS F-flag only",
			input: []byte{
				0x80,       // Flags: F = 10000000
				0x00,       // Reserved
				0x00, 0x64, // Range Size = 100
			},
			proto:     base.ISISL1,
			wantFlags: 0x80,
			wantSize:  100,
			wantErr:   false,
		},
		{
			name: "IS-IS M and S flags",
			input: []byte{
				0x60,       // Flags: M|S = 01100000
				0x00,       // Reserved
				0x01, 0x00, // Range Size = 256
			},
			proto:     base.ISISL2,
			wantFlags: 0x60,
			wantSize:  256,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalRangeTLV(tt.input, tt.proto)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalRangeTLV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if got.Flags.GetRangeFlagsByte() != tt.wantFlags {
					t.Errorf("Flags = 0x%02X, want 0x%02X", got.Flags.GetRangeFlagsByte(), tt.wantFlags)
				}
				if got.RangeSize != tt.wantSize {
					t.Errorf("RangeSize = %d, want %d", got.RangeSize, tt.wantSize)
				}
			}
		})
	}
}

func TestUnmarshalRangeTLV_OSPF(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		proto    base.ProtoID
		wantIA   bool
		wantSize uint16
	}{
		{
			name: "OSPF IA flag set",
			input: []byte{
				0x80,       // Flags: IA = 10000000
				0x00,       // Reserved
				0x00, 0x05, // Range Size = 5
			},
			proto:    base.OSPFv2,
			wantIA:   true,
			wantSize: 5,
		},
		{
			name: "OSPF IA flag clear",
			input: []byte{
				0x00,       // Flags: IA = 0
				0x00,       // Reserved
				0x00, 0x14, // Range Size = 20
			},
			proto:    base.OSPFv2,
			wantIA:   false,
			wantSize: 20,
		},
		{
			name: "OSPFv3 IA flag set",
			input: []byte{
				0x80,       // Flags: IA = 10000000
				0x00,       // Reserved
				0x00, 0xFF, // Range Size = 255
			},
			proto:    base.OSPFv3,
			wantIA:   true,
			wantSize: 255,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalRangeTLV(tt.input, tt.proto)
			if err != nil {
				t.Fatalf("UnmarshalRangeTLV() error = %v", err)
			}

			ospfFlags, ok := got.Flags.(*OSPFRangeFlags)
			if !ok {
				t.Fatal("Flags not OSPFRangeFlags type")
			}

			if ospfFlags.IAFlag != tt.wantIA {
				t.Errorf("IAFlag = %v, want %v", ospfFlags.IAFlag, tt.wantIA)
			}
			if got.RangeSize != tt.wantSize {
				t.Errorf("RangeSize = %d, want %d", got.RangeSize, tt.wantSize)
			}
		})
	}
}

func TestUnmarshalRangeTLV_UnknownProto(t *testing.T) {
	input := []byte{
		0xAB,       // Flags: arbitrary value
		0x00,       // Reserved
		0x00, 0x2A, // Range Size = 42
	}

	got, err := UnmarshalRangeTLV(input, base.ProtoID(99))
	if err != nil {
		t.Fatalf("UnmarshalRangeTLV() error = %v", err)
	}

	unknownFlags, ok := got.Flags.(*UnknownProtoRangeFlags)
	if !ok {
		t.Fatal("Flags not UnknownProtoRangeFlags type")
	}

	if unknownFlags.Flags != 0xAB {
		t.Errorf("Flags = 0x%02X, want 0xAB", unknownFlags.Flags)
	}
	if got.RangeSize != 42 {
		t.Errorf("RangeSize = %d, want 42", got.RangeSize)
	}
}

func TestUnmarshalRangeTLV_TooShort(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"Empty", []byte{}},
		{"OneByte", []byte{0x00}},
		{"TwoBytes", []byte{0x00, 0x00}},
		{"ThreeBytes", []byte{0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalRangeTLV(tt.input, base.ISISL2)
			if err == nil {
				t.Error("UnmarshalRangeTLV() expected error for truncated data, got nil")
			}
		})
	}
}

func TestUnmarshalRangeTLV_LargeRangeSize(t *testing.T) {
	input := []byte{
		0x00,       // Flags
		0x00,       // Reserved
		0xFF, 0xFF, // Range Size = 65535 (max uint16)
	}

	got, err := UnmarshalRangeTLV(input, base.ISISL2)
	if err != nil {
		t.Fatalf("UnmarshalRangeTLV() error = %v", err)
	}

	if got.RangeSize != 65535 {
		t.Errorf("RangeSize = %d, want 65535", got.RangeSize)
	}
}

func TestUnmarshalRangeTLVFlags_ISIS(t *testing.T) {
	tests := []struct {
		name  string
		flags byte
		want  ISISRangeFlags
	}{
		{
			name:  "All flags set",
			flags: 0xF8,
			want:  ISISRangeFlags{FFlag: true, MFlag: true, SFlag: true, DFlag: true, AFlag: true},
		},
		{
			name:  "No flags set",
			flags: 0x00,
			want:  ISISRangeFlags{FFlag: false, MFlag: false, SFlag: false, DFlag: false, AFlag: false},
		},
		{
			name:  "Only F-flag",
			flags: 0x80,
			want:  ISISRangeFlags{FFlag: true, MFlag: false, SFlag: false, DFlag: false, AFlag: false},
		},
		{
			name:  "D and A flags",
			flags: 0x18,
			want:  ISISRangeFlags{FFlag: false, MFlag: false, SFlag: false, DFlag: true, AFlag: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalRangeTLVFlags(tt.flags, base.ISISL2)
			if err != nil {
				t.Fatalf("UnmarshalRangeTLVFlags() error = %v", err)
			}

			isisFlags, ok := got.(*ISISRangeFlags)
			if !ok {
				t.Fatal("Flags not ISISRangeFlags type")
			}

			if *isisFlags != tt.want {
				t.Errorf("Flags = %+v, want %+v", *isisFlags, tt.want)
			}
		})
	}
}

func TestGetLSRangeTLV(t *testing.T) {
	tests := []struct {
		name    string
		tlvs    []TLV
		proto   base.ProtoID
		wantErr bool
	}{
		{
			name: "Range TLV present",
			tlvs: []TLV{
				{
					Type:  1159,
					Value: []byte{0x80, 0x00, 0x00, 0x0A},
				},
			},
			proto:   base.ISISL2,
			wantErr: false,
		},
		{
			name:    "Range TLV not present",
			tlvs:    []TLV{},
			proto:   base.ISISL2,
			wantErr: true,
		},
		{
			name: "Multiple TLVs with Range",
			tlvs: []TLV{
				{Type: 1158, Value: []byte{0x00}},
				{Type: 1159, Value: []byte{0x00, 0x00, 0x00, 0x01}},
				{Type: 1171, Value: []byte{10, 0, 0, 1}},
			},
			proto:   base.OSPFv2,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: tt.tlvs}
			got, err := nlri.GetLSRangeTLV(tt.proto)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetLSRangeTLV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Error("GetLSRangeTLV() returned nil without error")
			}
		})
	}
}
