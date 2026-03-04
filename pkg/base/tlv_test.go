package base

import (
	"testing"
)

func TestUnmarshalTLV(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		// expected map contents when wantErr is false
		wantTypes  []uint16
		wantValues [][]byte
	}{
		{
			// Type field requires 2 bytes; only 1 byte supplied.
			name:    "truncated type field",
			input:   []byte{0x02},
			wantErr: true,
		},
		{
			// Type (2 bytes) read OK, but length field requires 2 bytes and only 1 remains.
			name:    "truncated length field",
			input:   []byte{0x02, 0x00, 0x00},
			wantErr: true,
		},
		{
			// Type (2 bytes) + Length (2 bytes, value=3) read OK, but only 2 value bytes present.
			name:    "truncated value field",
			input:   []byte{0x02, 0x00, 0x00, 0x03, 0xAA, 0xBB},
			wantErr: true,
		},
		{
			// Two TLVs with the same type code — violates RFC 7752.
			name: "duplicate TLV type",
			input: []byte{
				0x02, 0x00, 0x00, 0x02, 0xAA, 0xBB, // type=512, len=2, value=0xAABB
				0x02, 0x00, 0x00, 0x02, 0xCC, 0xDD, // type=512, len=2, value=0xCCDD (duplicate)
			},
			wantErr: true,
		},
		{
			// Two well-formed TLVs with distinct type codes.
			name: "two valid distinct TLVs",
			input: []byte{
				0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2A, // type=512, len=4, value=42
				0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x07, // type=513, len=4, value=7
			},
			wantErr:    false,
			wantTypes:  []uint16{512, 513},
			wantValues: [][]byte{{0x00, 0x00, 0x00, 0x2A}, {0x00, 0x00, 0x00, 0x07}},
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
			for i, typ := range tt.wantTypes {
				tlv, ok := got[typ]
				if !ok {
					t.Fatalf("expected TLV type %d not found in result", typ)
				}
				if int(tlv.Length) != len(tt.wantValues[i]) {
					t.Fatalf("TLV type %d: length = %d, want %d", typ, tlv.Length, len(tt.wantValues[i]))
				}
				if len(tlv.Value) != len(tt.wantValues[i]) {
					t.Fatalf("TLV type %d: value length = %d, want %d", typ, len(tlv.Value), len(tt.wantValues[i]))
				}
				for j, b := range tt.wantValues[i] {
					if tlv.Value[j] != b {
						t.Fatalf("TLV type %d: value[%d] = 0x%02x, want 0x%02x", typ, j, tlv.Value[j], b)
					}
				}
			}
		})
	}
}
func TestUnmarshalSubTLV(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantErr  bool
		wantLen  int
		wantType uint16
	}{
		{
			name:    "truncated type",
			input:   []byte{0x01},
			wantErr: true,
		},
		{
			name:    "truncated length",
			input:   []byte{0x00, 0x01, 0x00},
			wantErr: true,
		},
		{
			name:    "truncated value",
			input:   []byte{0x00, 0x01, 0x00, 0x03, 0xAA, 0xBB},
			wantErr: true,
		},
		{
			name:     "single valid sub-TLV",
			input:    []byte{0x00, 0x05, 0x00, 0x02, 0xAB, 0xCD},
			wantErr:  false,
			wantLen:  1,
			wantType: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSubTLV(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalSubTLV() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != tt.wantLen {
				t.Fatalf("len(got) = %d, want %d", len(got), tt.wantLen)
			}
			if got[0].Type != tt.wantType {
				t.Errorf("Type = %d, want %d", got[0].Type, tt.wantType)
			}
		})
	}
}
