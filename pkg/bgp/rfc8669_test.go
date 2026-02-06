package bgp

import (
	"reflect"
	"testing"
)

// TestRFC8669_LabelIndex validates Label-Index TLV (Type 1) parsing per RFC 8669 Section 3.1.
// Wire format: Reserved (1 byte) + Flags (2 bytes) + Label Index (4 bytes) = 7 bytes total.
func TestRFC8669_LabelIndex(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *BGPPrefixSID
		wantErr bool
	}{
		{
			name: "Standard allocation index 100",
			input: []byte{
				0x01,       // Type 1 (Label-Index)
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x00, // Flags
				0x00, 0x00, 0x00, 0x64, // Label Index (100)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 100,
						},
					},
				},
			},
		},
		{
			name: "Zero index",
			input: []byte{
				0x01,       // Type 1
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x00, // Flags
				0x00, 0x00, 0x00, 0x00, // Label Index (0)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 0,
						},
					},
				},
			},
		},
		{
			name: "Large index 999999",
			input: []byte{
				0x01,       // Type 1
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x00, // Flags
				0x00, 0x0F, 0x42, 0x3F, // Label Index (999999)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 999999,
						},
					},
				},
			},
		},
		{
			name: "Max uint32 index",
			input: []byte{
				0x01,       // Type 1
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x00, // Flags
				0xFF, 0xFF, 0xFF, 0xFF, // Label Index (4294967295)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 4294967295,
						},
					},
				},
			},
		},
		{
			name: "With flags set",
			input: []byte{
				0x01,       // Type 1
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x01, // Flags (1)
				0x00, 0x00, 0x0A, 0xBC, // Label Index (2748)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      1,
							LabelIndex: 2748,
						},
					},
				},
			},
		},
		{
			name: "Cisco IOS-XR default SRGB start index 16000",
			input: []byte{
				0x01,       // Type 1
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x00, // Flags
				0x00, 0x00, 0x3E, 0x80, // Label Index (16000)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 16000,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBGPPrefixSID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBGPPrefixSID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalBGPPrefixSID() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRFC8669_OriginatorSRGB validates Originator SRGB TLV (Type 3) parsing per RFC 8669 Section 3.2.
// Wire format: Flags (2 bytes) + SRGB Ranges (6 bytes each: 3-byte base + 3-byte range).
func TestRFC8669_OriginatorSRGB(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *BGPPrefixSID
		wantErr bool
	}{
		{
			name: "Default SRGB 16000 range 8000",
			input: []byte{
				0x03,       // Type 3 (Originator SRGB)
				0x00, 0x08, // Length 8 (2 flags + 6 range)
				0x00, 0x00, // Flags
				0x00, 0x3E, 0x80, // Base (16000)
				0x00, 0x1F, 0x40, // Range (8000)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   3,
						Length: 8,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 16000, Range: 8000},
							},
						},
					},
				},
			},
		},
		{
			name: "Large SRGB base 100000 range 50000",
			input: []byte{
				0x03,       // Type 3
				0x00, 0x08, // Length 8
				0x00, 0x00, // Flags
				0x01, 0x86, 0xA0, // Base (100000)
				0x00, 0xC3, 0x50, // Range (50000)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   3,
						Length: 8,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 100000, Range: 50000},
							},
						},
					},
				},
			},
		},
		{
			name: "Three SRGB ranges",
			input: []byte{
				0x03,       // Type 3
				0x00, 0x14, // Length 20 (2 flags + 3*6 ranges)
				0x00, 0x00, // Flags
				0x00, 0x3E, 0x80, // Base 1 (16000)
				0x00, 0x1F, 0x40, // Range 1 (8000)
				0x00, 0x61, 0xA8, // Base 2 (25000)
				0x00, 0x13, 0x88, // Range 2 (5000)
				0x00, 0x7A, 0x12, // Base 3 (31250)
				0x00, 0x03, 0xE8, // Range 3 (1000)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   3,
						Length: 20,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 16000, Range: 8000},
								{Base: 25000, Range: 5000},
								{Base: 31250, Range: 1000},
							},
						},
					},
				},
			},
		},
		{
			name: "Max 24-bit values",
			input: []byte{
				0x03,       // Type 3
				0x00, 0x08, // Length 8
				0x00, 0x00, // Flags
				0xFF, 0xFF, 0xFF, // Base (16777215)
				0xFF, 0xFF, 0xFF, // Range (16777215)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   3,
						Length: 8,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 16777215, Range: 16777215},
							},
						},
					},
				},
			},
		},
		{
			name: "Zero range value",
			input: []byte{
				0x03,       // Type 3
				0x00, 0x08, // Length 8
				0x00, 0x00, // Flags
				0x00, 0x3E, 0x80, // Base (16000)
				0x00, 0x00, 0x00, // Range (0)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   3,
						Length: 8,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 16000, Range: 0},
							},
						},
					},
				},
			},
		},
		{
			name: "Juniper-style dual SRGB ranges",
			input: []byte{
				0x03,       // Type 3
				0x00, 0x0E, // Length 14 (2 flags + 2*6 ranges)
				0x00, 0x00, // Flags
				0x00, 0x3E, 0x80, // Base 1 (16000)
				0x00, 0x1F, 0x40, // Range 1 (8000)
				0x06, 0x1A, 0x80, // Base 2 (400000)
				0x01, 0x86, 0xA0, // Range 2 (100000)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   3,
						Length: 14,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 16000, Range: 8000},
								{Base: 400000, Range: 100000},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBGPPrefixSID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBGPPrefixSID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalBGPPrefixSID() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRFC8669_CompletePrefixSID validates complete BGP Prefix-SID attribute with multiple TLVs.
func TestRFC8669_CompletePrefixSID(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *BGPPrefixSID
		wantErr bool
	}{
		{
			name: "Label-Index TLV only",
			input: []byte{
				0x01,       // Type 1
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x00, // Flags
				0x00, 0x00, 0x00, 0x64, // Label Index (100)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 100,
						},
					},
				},
			},
		},
		{
			name: "Originator SRGB TLV only",
			input: []byte{
				0x03,       // Type 3
				0x00, 0x08, // Length 8
				0x00, 0x00, // Flags
				0x00, 0x3E, 0x80, // Base (16000)
				0x00, 0x1F, 0x40, // Range (8000)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   3,
						Length: 8,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 16000, Range: 8000},
							},
						},
					},
				},
			},
		},
		{
			name: "Both Type 1 and Type 3",
			input: []byte{
				// Type 1 (Label-Index)
				0x01,       // Type 1
				0x00, 0x07, // Length 7
				0x00,       // Reserved
				0x00, 0x00, // Flags
				0x00, 0x00, 0x00, 0x64, // Label Index (100)
				// Type 3 (Originator SRGB)
				0x03,       // Type 3
				0x00, 0x08, // Length 8
				0x00, 0x00, // Flags
				0x00, 0x3E, 0x80, // Base (16000)
				0x00, 0x1F, 0x40, // Range (8000)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 100,
						},
					},
					{
						Type:   3,
						Length: 8,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 16000, Range: 8000},
							},
						},
					},
				},
			},
		},
		{
			name: "Cisco IOS-XR scenario: index 100 with default SRGB 16000-23999",
			input: []byte{
				// Label-Index: 100
				0x01, 0x00, 0x07,
				0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x64,
				// SRGB: Base=16000, Range=8000
				0x03, 0x00, 0x08,
				0x00, 0x00,
				0x00, 0x3E, 0x80,
				0x00, 0x1F, 0x40,
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 100,
						},
					},
					{
						Type:   3,
						Length: 8,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 16000, Range: 8000},
							},
						},
					},
				},
			},
		},
		{
			name: "Juniper MX scenario: index 1000 with dual SRGB ranges",
			input: []byte{
				// Label-Index: 1000
				0x01, 0x00, 0x07,
				0x00, 0x00, 0x00,
				0x00, 0x00, 0x03, 0xE8,
				// SRGB: dual ranges
				0x03, 0x00, 0x0E, // Length 14
				0x00, 0x00,       // Flags
				0x00, 0x3E, 0x80, // Base 1 (16000)
				0x00, 0x1F, 0x40, // Range 1 (8000)
				0x06, 0x1A, 0x80, // Base 2 (400000)
				0x01, 0x86, 0xA0, // Range 2 (100000)
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 1000,
						},
					},
					{
						Type:   3,
						Length: 14,
						OriginatorSRGB: &OriginatorSRGBTLV{
							Flags: 0,
							Ranges: []SRGBRange{
								{Base: 16000, Range: 8000},
								{Base: 400000, Range: 100000},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBGPPrefixSID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBGPPrefixSID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalBGPPrefixSID() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRFC8669_ForwardCompatibility validates that unknown TLV types are preserved per RFC 8669
// forward compatibility requirements.
func TestRFC8669_ForwardCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *BGPPrefixSID
		wantErr bool
	}{
		{
			name: "Unknown type 5 preserved as raw bytes",
			input: []byte{
				0x05,       // Type 5 (unknown/future SRv6 L3 Service)
				0x00, 0x04, // Length 4
				0xCA, 0xFE, 0xBA, 0xBE,
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:         5,
						Length:       4,
						UnknownValue: []byte{0xCA, 0xFE, 0xBA, 0xBE},
					},
				},
			},
		},
		{
			name: "Multiple unknown types preserved",
			input: []byte{
				// Type 5
				0x05, 0x00, 0x02,
				0xAA, 0xBB,
				// Type 6
				0x06, 0x00, 0x03,
				0xCC, 0xDD, 0xEE,
				// Type 7
				0x07, 0x00, 0x01,
				0xFF,
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:         5,
						Length:       2,
						UnknownValue: []byte{0xAA, 0xBB},
					},
					{
						Type:         6,
						Length:       3,
						UnknownValue: []byte{0xCC, 0xDD, 0xEE},
					},
					{
						Type:         7,
						Length:       1,
						UnknownValue: []byte{0xFF},
					},
				},
			},
		},
		{
			name: "Known Type 1 mixed with unknown Type 99",
			input: []byte{
				// Type 1 (Label-Index)
				0x01, 0x00, 0x07,
				0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x64, // Index 100
				// Type 99 (unknown)
				0x63, 0x00, 0x03,
				0x01, 0x02, 0x03,
			},
			want: &BGPPrefixSID{
				TLVs: []BGPPrefixSIDTLV{
					{
						Type:   1,
						Length: 7,
						LabelIndex: &LabelIndexTLV{
							Flags:      0,
							LabelIndex: 100,
						},
					},
					{
						Type:         99,
						Length:       3,
						UnknownValue: []byte{0x01, 0x02, 0x03},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBGPPrefixSID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBGPPrefixSID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalBGPPrefixSID() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRFC8669_ErrorCases validates error handling for malformed Prefix-SID attributes.
func TestRFC8669_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "Empty attribute",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "TLV header only - 2 bytes",
			input:   []byte{0x01, 0x00},
			wantErr: true,
		},
		{
			name: "TLV length exceeds remaining data",
			input: []byte{
				0x01,       // Type 1
				0x00, 0xFF, // Length 255
				0x00, 0x00, 0x00, 0x00, // Only 4 bytes of data
			},
			wantErr: true,
		},
		{
			name: "Label-Index TLV too short",
			input: []byte{
				0x01,       // Type 1
				0x00, 0x03, // Length 3 (needs 7)
				0x00, 0x00, 0x00,
			},
			wantErr: true,
		},
		{
			name: "SRGB with incomplete range",
			input: []byte{
				0x03,       // Type 3
				0x00, 0x05, // Length 5 (flags=2 + 3 bytes, needs 6 for a range)
				0x00, 0x00, // Flags
				0x00, 0x27, 0x10, // Incomplete range (only base, no range value)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalBGPPrefixSID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBGPPrefixSID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
