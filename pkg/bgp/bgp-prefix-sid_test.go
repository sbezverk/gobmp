package bgp

import (
	"reflect"
	"testing"
)

func TestUnmarshalLabelIndexTLV(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *LabelIndexTLV
		wantErr bool
	}{
		{
			name: "Valid Label-Index TLV",
			input: []byte{
				0x00,       // Reserved
				0x00, 0x00, // Flags (0)
				0x00, 0x00, 0x0A, 0xBC, // Label Index (2748)
			},
			want: &LabelIndexTLV{
				Flags:      0,
				LabelIndex: 2748,
			},
			wantErr: false,
		},
		{
			name: "Label-Index TLV with flags",
			input: []byte{
				0x00,       // Reserved
				0x00, 0x01, // Flags (1)
				0x00, 0x01, 0x86, 0xA0, // Label Index (100000)
			},
			want: &LabelIndexTLV{
				Flags:      1,
				LabelIndex: 100000,
			},
			wantErr: false,
		},
		{
			name:    "Invalid length - too short",
			input:   []byte{0x00, 0x00, 0x00},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Invalid length - empty",
			input:   []byte{},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unmarshalLabelIndexTLV(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("unmarshalLabelIndexTLV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unmarshalLabelIndexTLV() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestUnmarshalOriginatorSRGBTLV(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *OriginatorSRGBTLV
		wantErr bool
	}{
		{
			name: "Valid Originator SRGB with single range",
			input: []byte{
				0x00, 0x00, // Flags
				0x00, 0x27, 0x10, // Base (10000)
				0x00, 0x03, 0xE8, // Range (1000)
			},
			want: &OriginatorSRGBTLV{
				Flags: 0,
				Ranges: []SRGBRange{
					{Base: 10000, Range: 1000},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid Originator SRGB with multiple ranges",
			input: []byte{
				0x00, 0x01, // Flags (1)
				0x00, 0x27, 0x10, // Base 1 (10000)
				0x00, 0x03, 0xE8, // Range 1 (1000)
				0x00, 0x4E, 0x20, // Base 2 (20000)
				0x00, 0x07, 0xD0, // Range 2 (2000)
			},
			want: &OriginatorSRGBTLV{
				Flags: 1,
				Ranges: []SRGBRange{
					{Base: 10000, Range: 1000},
					{Base: 20000, Range: 2000},
				},
			},
			wantErr: false,
		},
		{
			name:    "Invalid length - too short for flags",
			input:   []byte{0x00},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Invalid length - incomplete range",
			input: []byte{
				0x00, 0x00, // Flags
				0x00, 0x27, 0x10, // Base (10000)
				0x00, 0x03, // Incomplete range (only 2 bytes)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Valid SRGB with no ranges (only flags)",
			input: []byte{
				0x00, 0x00, // Flags only
			},
			want: &OriginatorSRGBTLV{
				Flags:  0,
				Ranges: []SRGBRange{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unmarshalOriginatorSRGBTLV(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("unmarshalOriginatorSRGBTLV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unmarshalOriginatorSRGBTLV() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestUnmarshalBGPPrefixSID(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *BGPPrefixSID
		wantErr bool
	}{
		{
			name: "Valid BGP Prefix-SID with Label-Index TLV",
			input: []byte{
				0x01,       // Type 1 (Label-Index)
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x00, // Flags
				0x00, 0x00, 0x0A, 0xBC, // Label Index (2748)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 2748,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid BGP Prefix-SID with Originator SRGB TLV",
			input: []byte{
				0x03,       // Type 3 (Originator SRGB)
				0x00, 0x08, // Length 8
				0x00, 0x00, // Flags
				0x00, 0x27, 0x10, // Base (10000)
				0x00, 0x03, 0xE8, // Range (1000)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   3,
						Length: 8,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 10000, Range: 1000},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Multiple TLVs in single attribute",
			input: []byte{
				0x01,       // Type 1 (Label-Index)
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x00, // Flags
				0x00, 0x00, 0x0A, 0xBC, // Label Index (2748)
				0x03,       // Type 3 (Originator SRGB)
				0x00, 0x08, // Length 8
				0x00, 0x00, // Flags
				0x00, 0x27, 0x10, // Base (10000)
				0x00, 0x03, 0xE8, // Range (1000)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 2748,
						},
					},
					{
						Type:   3,
						Length: 8,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 10000, Range: 1000},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Unknown TLV type (preserved as raw bytes)",
			input: []byte{
				0xFF,       // Type 255 (unknown)
				0x00, 0x04, // Length 4
				0xDE, 0xAD, 0xBE, 0xEF, // Value
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:         255,
						Length:       4,
						UnknownValue: []byte{0xDE, 0xAD, 0xBE, 0xEF},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Mixed known and unknown TLVs",
			input: []byte{
				0x01,       // Type 1 (Label-Index)
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x00, // Flags
				0x00, 0x00, 0x0A, 0xBC, // Label Index (2748)
				0xAA,       // Type 170 (unknown)
				0x00, 0x02, // Length 2
				0x12, 0x34, // Value
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 2748,
						},
					},
					{
						Type:         170,
						Length:       2,
						UnknownValue: []byte{0x12, 0x34},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "Invalid - too short",
			input:   []byte{0x01, 0x00},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Invalid - TLV length exceeds data",
			input: []byte{
				0x01,       // Type 1
				0x00, 0xFF, // Length 255 (but we don't have that much data)
				0x00, 0x00, 0x00, 0x00,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Invalid Label-Index TLV within Prefix-SID",
			input: []byte{
				0x01,       // Type 1 (Label-Index)
				0x00, 0x03, // Length 3 (invalid - should be 7)
				0x00, 0x00, 0x00,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Invalid Originator SRGB TLV within Prefix-SID",
			input: []byte{
				0x03,       // Type 3 (Originator SRGB)
				0x00, 0x05, // Length 5
				0x00, 0x00, // Flags
				0x00, 0x27, 0x10, // Incomplete range
			},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Empty attribute",
			input:   []byte{},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBGPPrefixSID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBGPPrefixSID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalBGPPrefixSID() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestBGPPrefixSIDIntegrationWithBaseAttributes(t *testing.T) {
	// Test that BGP Prefix-SID integrates correctly with BaseAttributes
	// This simulates attribute 40 being parsed

	// Create a simple path attribute with BGP Prefix-SID (attribute 40)
	prefixSIDData := []byte{
		0x01,       // Type 1 (Label-Index)
		0x00, 0x07, // Length 7
		0x00,       // Reserved
		0x00, 0x00, // Flags
		0x00, 0x00, 0x0A, 0xBC, // Label Index (2748)
	}

	// Test direct unmarshal
	sid, err := UnmarshalBGPPrefixSID(prefixSIDData)
	if err != nil {
		t.Fatalf("Failed to unmarshal BGP Prefix-SID: %v", err)
	}

	if len(sid.TLVs) != 1 {
		t.Errorf("Expected 1 TLV, got %d", len(sid.TLVs))
	}

	if sid.TLVs[0].Type != 1 {
		t.Errorf("Expected TLV type 1, got %d", sid.TLVs[0].Type)
	}

	if sid.TLVs[0].LabelIndex == nil {
		t.Fatal("Expected LabelIndex to be non-nil")
	}

	if sid.TLVs[0].LabelIndex.LabelIndex != 2748 {
		t.Errorf("Expected Label Index 2748, got %d", sid.TLVs[0].LabelIndex.LabelIndex)
	}
}

func TestSRGBRangeLargeValues(t *testing.T) {
	// Test SRGB ranges with maximum 24-bit values
	input := []byte{
		0x00, 0x00, // Flags
		0xFF, 0xFF, 0xFF, // Base (16777215 - max 24-bit)
		0xFF, 0xFF, 0xFF, // Range (16777215 - max 24-bit)
	}

	got, err := unmarshalOriginatorSRGBTLV(input)
	if err != nil {
		t.Fatalf("unmarshalOriginatorSRGBTLV() error = %v", err)
	}

	if len(got.Ranges) != 1 {
		t.Fatalf("Expected 1 range, got %d", len(got.Ranges))
	}

	expectedBase := uint32(16777215)
	expectedRange := uint32(16777215)

	if got.Ranges[0].Base != expectedBase {
		t.Errorf("Expected base %d, got %d", expectedBase, got.Ranges[0].Base)
	}

	if got.Ranges[0].Range != expectedRange {
		t.Errorf("Expected range %d, got %d", expectedRange, got.Ranges[0].Range)
	}
}
