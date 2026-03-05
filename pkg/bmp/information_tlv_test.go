package bmp

import (
	"encoding/binary"
	"testing"
)

func TestUnmarshalTLV(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantErr     bool
		wantCount   int
		wantTypes   []uint16
		wantLengths []uint16
	}{
		{
			name:      "empty input returns empty slice",
			input:     []byte{},
			wantErr:   false,
			wantCount: 0,
		},
		{
			name: "single TLV type=0 length=5",
			input: func() []byte {
				b := make([]byte, 4+5)
				binary.BigEndian.PutUint16(b[0:], 0)
				binary.BigEndian.PutUint16(b[2:], 5)
				copy(b[4:], []byte("hello"))
				return b
			}(),
			wantErr:     false,
			wantCount:   1,
			wantTypes:   []uint16{0},
			wantLengths: []uint16{5},
		},
		{
			name: "two TLVs back-to-back",
			input: func() []byte {
				b := make([]byte, 4+3+4+4)
				binary.BigEndian.PutUint16(b[0:], 1)
				binary.BigEndian.PutUint16(b[2:], 3)
				copy(b[4:], []byte("foo"))
				binary.BigEndian.PutUint16(b[7:], 2)
				binary.BigEndian.PutUint16(b[9:], 4)
				copy(b[11:], []byte("bars"))
				return b
			}(),
			wantErr:     false,
			wantCount:   2,
			wantTypes:   []uint16{1, 2},
			wantLengths: []uint16{3, 4},
		},
		{
			name:      "single TLV zero-length value",
			input:     []byte{0x00, 0x05, 0x00, 0x00},
			wantErr:   false,
			wantCount: 1,
			wantTypes: []uint16{5},
		},
		{
			name:    "truncated: only 1 byte (type read needs 2)",
			input:   []byte{0x00},
			wantErr: true,
		},
		{
			name:    "truncated: only 3 bytes (length read needs 2 more after type)",
			input:   []byte{0x00, 0x01, 0x00},
			wantErr: true,
		},
		{
			name:    "value overflows buffer",
			input:   []byte{0x00, 0x00, 0x00, 0x0A, 0x01, 0x02}, // length=10 but only 2 bytes of value
			wantErr: true,
		},
		{
			name: "unknown TLV type is accepted (extensibility)",
			input: func() []byte {
				b := make([]byte, 4+2)
				binary.BigEndian.PutUint16(b[0:], 999)
				binary.BigEndian.PutUint16(b[2:], 2)
				b[4] = 0xCA
				b[5] = 0xFE
				return b
			}(),
			wantErr:   false,
			wantCount: 1,
			wantTypes: []uint16{999},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalTLV(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalTLV() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != tt.wantCount {
				t.Fatalf("UnmarshalTLV() returned %d TLVs, want %d", len(got), tt.wantCount)
			}
			for i, wantType := range tt.wantTypes {
				if got[i].InformationType != wantType {
					t.Errorf("TLV[%d].InformationType = %d, want %d", i, got[i].InformationType, wantType)
				}
			}
			for i, wantLen := range tt.wantLengths {
				if got[i].InformationLength != wantLen {
					t.Errorf("TLV[%d].InformationLength = %d, want %d", i, got[i].InformationLength, wantLen)
				}
			}
		})
	}
}

func TestUnmarshalInitiationMessage(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantErr   bool
		wantCount int
		wantTypes []uint16
	}{
		{
			name:      "empty input returns empty TLV list",
			input:     []byte{},
			wantErr:   false,
			wantCount: 0,
		},
		{
			name: "sysDescr TLV (type=1) only",
			input: func() []byte {
				desc := []byte("Cisco IOS XR")
				b := make([]byte, 4+len(desc))
				binary.BigEndian.PutUint16(b[0:], 1)
				binary.BigEndian.PutUint16(b[2:], uint16(len(desc)))
				copy(b[4:], desc)
				return b
			}(),
			wantErr:   false,
			wantCount: 1,
			wantTypes: []uint16{1},
		},
		{
			name: "sysName TLV (type=2) and sysDescr TLV (type=1)",
			input: func() []byte {
				name := []byte("router1.example.com")
				desc := []byte("Cisco IOS XR 7.11")
				b := make([]byte, 4+len(name)+4+len(desc))
				binary.BigEndian.PutUint16(b[0:], 2)
				binary.BigEndian.PutUint16(b[2:], uint16(len(name)))
				copy(b[4:], name)
				off := 4 + len(name)
				binary.BigEndian.PutUint16(b[off:], 1)
				binary.BigEndian.PutUint16(b[off+2:], uint16(len(desc)))
				copy(b[off+4:], desc)
				return b
			}(),
			wantErr:   false,
			wantCount: 2,
			wantTypes: []uint16{2, 1},
		},
		{
			name: "unknown TLV type skipped (extensibility per RFC 7854)",
			input: func() []byte {
				b := make([]byte, 4+3)
				binary.BigEndian.PutUint16(b[0:], 99) // unknown type
				binary.BigEndian.PutUint16(b[2:], 3)
				copy(b[4:], []byte("ext"))
				return b
			}(),
			wantErr:   false,
			wantCount: 1,
			wantTypes: []uint16{99},
		},
		{
			name:    "truncated TLV header (only 1 byte)",
			input:   []byte{0x00},
			wantErr: true,
		},
		{
			name:    "truncated TLV header (only 3 bytes — length field incomplete)",
			input:   []byte{0x00, 0x01, 0x00},
			wantErr: true,
		},
		{
			name:    "value overflows buffer",
			input:   []byte{0x00, 0x01, 0x00, 0x10, 0xAA, 0xBB}, // length=16 but 2 value bytes
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalInitiationMessage(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalInitiationMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got.TLV) != tt.wantCount {
				t.Fatalf("UnmarshalInitiationMessage() returned %d TLVs, want %d", len(got.TLV), tt.wantCount)
			}
			for i, wantType := range tt.wantTypes {
				if got.TLV[i].InformationType != wantType {
					t.Errorf("TLV[%d].InformationType = %d, want %d", i, got.TLV[i].InformationType, wantType)
				}
			}
		})
	}
}
