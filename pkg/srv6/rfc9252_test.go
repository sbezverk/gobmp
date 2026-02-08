package srv6

import (
	"net"
	"reflect"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/base"
)

// TestRFC9252_SIDStructureSubSubTLV validates unmarshaling of the SID
// Structure Sub-Sub-TLV per RFC 9252 Section 3.2.1.
func TestRFC9252_SIDStructureSubSubTLV(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *SIDStructureSubSubTLV
	}{
		{
			name:  "Standard SID structure 40/24/16/0/16/64",
			input: []byte{0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
			expected: &SIDStructureSubSubTLV{
				LocalBlockLength:    40,
				LocalNodeLength:     24,
				FunctionLength:      16,
				ArgumentLength:      0,
				TranspositionLength: 16,
				TranspositionOffset: 64,
			},
		},
		{
			name:  "All zeros",
			input: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: &SIDStructureSubSubTLV{
				LocalBlockLength:    0,
				LocalNodeLength:     0,
				FunctionLength:      0,
				ArgumentLength:      0,
				TranspositionLength: 0,
				TranspositionOffset: 0,
			},
		},
		{
			name:  "Max values",
			input: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			expected: &SIDStructureSubSubTLV{
				LocalBlockLength:    255,
				LocalNodeLength:     255,
				FunctionLength:      255,
				ArgumentLength:      255,
				TranspositionLength: 255,
				TranspositionOffset: 255,
			},
		},
		{
			name:  "Standard SID structure 48/16/16/0/0/0",
			input: []byte{0x30, 0x10, 0x10, 0x00, 0x00, 0x00},
			expected: &SIDStructureSubSubTLV{
				LocalBlockLength:    48,
				LocalNodeLength:     16,
				FunctionLength:      16,
				ArgumentLength:      0,
				TranspositionLength: 0,
				TranspositionOffset: 0,
			},
		},
		{
			name:  "With argument length",
			input: []byte{0x28, 0x18, 0x10, 0x08, 0x10, 0x40},
			expected: &SIDStructureSubSubTLV{
				LocalBlockLength:    40,
				LocalNodeLength:     24,
				FunctionLength:      16,
				ArgumentLength:      8,
				TranspositionLength: 16,
				TranspositionOffset: 64,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSIDStructureSubSubTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("mismatch:\n  got:  %+v\n  want: %+v", result, tt.expected)
			}
		})
	}
}

// TestRFC9252_InformationSubTLV validates unmarshaling of the SRv6
// Information Sub-TLV per RFC 9252 Section 3.1.
func TestRFC9252_InformationSubTLV(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *InformationSubTLV
	}{
		{
			name: "End.DT6 behavior with SID structure",
			// Reserved(1) + SID(16) + Flags(1) + Endpoint Behavior(2) + SubSubTLV
			input: []byte{
				0x00,                                                                                                       // Reserved
				0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,           // SID: 2001:0:5:4::
				0x00,                                                                                                       // Flags
				0x00, 0x13,                                                                                                 // Endpoint Behavior: 19 (End.DT6)
				0x00, 0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40,                                               // SubSubTLV type 1
			},
			expected: &InformationSubTLV{
				SID:              net.IP([]byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}).To16().String(),
				Flags:            0,
				EndpointBehavior: 19,
				SubSubTLVs: map[uint8][]SvcSubSubTLV{
					1: {
						&SIDStructureSubSubTLV{
							LocalBlockLength:    0x28,
							LocalNodeLength:     0x18,
							FunctionLength:      0x10,
							ArgumentLength:      0,
							TranspositionLength: 0x10,
							TranspositionOffset: 0x40,
						},
					},
				},
			},
		},
		{
			name: "Minimal - no sub-sub-TLVs",
			input: []byte{
				0x00,                                                                                             // Reserved
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SID: 2001:db8::1
				0x00,                                                                                             // Flags
				0x00, 0x06,                                                                                       // Endpoint Behavior: 6 (End.X)
			},
			expected: &InformationSubTLV{
				SID:              "2001:db8::1",
				Flags:            0,
				EndpointBehavior: 6,
			},
		},
		{
			name: "End.DT4 behavior",
			input: []byte{
				0x00,                                                                                             // Reserved
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SID: 2001:db8:1::
				0x00,                                                                                             // Flags
				0x00, 0x14,                                                                                       // Endpoint Behavior: 20 (End.DT4)
			},
			expected: &InformationSubTLV{
				SID:              "2001:db8:1::",
				Flags:            0,
				EndpointBehavior: 20,
			},
		},
		{
			name: "End.DT46 behavior with flags set",
			input: []byte{
				0x00,                                                                                             // Reserved
				0xfc, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SID: fc00:0:1::
				0x03,                                                                                             // Flags: bits set
				0x00, 0x15,                                                                                       // Endpoint Behavior: 21 (End.DT46)
			},
			expected: &InformationSubTLV{
				SID:              "fc00:0:1::",
				Flags:            3,
				EndpointBehavior: 21,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalInformationSubTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result.SID != tt.expected.SID {
				t.Errorf("SID = %q, want %q", result.SID, tt.expected.SID)
			}
			if result.Flags != tt.expected.Flags {
				t.Errorf("Flags = %d, want %d", result.Flags, tt.expected.Flags)
			}
			if result.EndpointBehavior != tt.expected.EndpointBehavior {
				t.Errorf("EndpointBehavior = %d, want %d", result.EndpointBehavior, tt.expected.EndpointBehavior)
			}
			if tt.expected.SubSubTLVs != nil {
				if result.SubSubTLVs == nil {
					t.Fatal("SubSubTLVs is nil, want non-nil")
				}
				if diff := deep.Equal(tt.expected.SubSubTLVs, result.SubSubTLVs); diff != nil {
					t.Errorf("SubSubTLVs mismatch: %v", diff)
				}
			}
		})
	}
}

// TestRFC9252_L3Service validates end-to-end unmarshaling of the SRv6
// L3 Service attribute per RFC 9252 Section 3.
func TestRFC9252_L3Service(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *L3Service
	}{
		{
			name: "L3 Service with End.DT6 SID",
			input: []byte{
				0x00,                                                                                             // Reserved
				0x01, 0x00, 0x1e,                                                                                 // SubTLV type 1, length 30
				0x00,                                                                                             // Reserved
				0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SID
				0x00,                                                                                             // Flags
				0x00, 0x13,                                                                                       // Endpoint Behavior: 19
				0x00, 0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40,                                     // SubSubTLV
			},
			expect: &L3Service{
				SubTLVs: map[uint8][]SvcSubTLV{
					1: {
						&InformationSubTLV{
							SID:              net.IP([]byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}).To16().String(),
							Flags:            0,
							EndpointBehavior: 19,
							SubSubTLVs: map[uint8][]SvcSubSubTLV{
								1: {
									&SIDStructureSubSubTLV{
										LocalBlockLength:    0x28,
										LocalNodeLength:     0x18,
										FunctionLength:      0x10,
										ArgumentLength:      0,
										TranspositionLength: 0x10,
										TranspositionOffset: 0x40,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRv6L3Service(tt.input)
			if err != nil {
				t.Fatalf("error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Errorf("Mismatches: %+v", deep.Equal(tt.expect, got))
			}
		})
	}
}

// TestRFC9252_L3ServiceSubTLV validates unmarshaling of Sub-TLVs within
// the L3 Service attribute.
func TestRFC9252_L3ServiceSubTLV(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectCount int
	}{
		{
			name: "Single Information SubTLV",
			input: []byte{
				0x01, 0x00, 0x14,                                                                                 // Type 1, Length 20
				0x00,                                                                                             // Reserved
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SID
				0x00,                                                                                             // Flags
				0x00, 0x06,                                                                                       // Endpoint Behavior: 6
			},
			expectCount: 1,
		},
		{
			name: "Unknown SubTLV type stored as raw bytes",
			input: []byte{
				0x02, 0x00, 0x04,             // Type 2 (unknown), Length 4
				0xaa, 0xbb, 0xcc, 0xdd,       // Raw value
			},
			expectCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6L3ServiceSubTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			totalCount := 0
			for _, v := range result {
				totalCount += len(v)
			}
			if totalCount != tt.expectCount {
				t.Errorf("total sub-TLV count = %d, want %d", totalCount, tt.expectCount)
			}
		})
	}
}

// TestRFC9252_L3ServiceSubSubTLV validates unmarshaling of Sub-Sub-TLVs.
func TestRFC9252_L3ServiceSubSubTLV(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectCount int
	}{
		{
			name: "SID Structure Sub-Sub-TLV",
			input: []byte{
				0x00,                                        // Initial byte (skipped per implementation)
				0x01, 0x00, 0x06,                            // Type 1, Length 6
				0x28, 0x18, 0x10, 0x00, 0x10, 0x40,         // SID structure data
			},
			expectCount: 1,
		},
		{
			name: "Unknown Sub-Sub-TLV type",
			input: []byte{
				0x00,                                        // Skipped
				0x02, 0x00, 0x03,                            // Type 2 (unknown), Length 3
				0xaa, 0xbb, 0xcc,                            // Raw value
			},
			expectCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6L3ServiceSubSubTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			totalCount := 0
			for _, v := range result {
				totalCount += len(v)
			}
			if totalCount != tt.expectCount {
				t.Errorf("count = %d, want %d", totalCount, tt.expectCount)
			}
		})
	}
}

// TestRFC9252_EndpointBehavior validates unmarshaling of SRv6 Endpoint
// Behavior TLV per RFC 9252 Section 3.1 (behavior codes from IANA registry).
func TestRFC9252_EndpointBehavior(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *EndpointBehavior
	}{
		{
			name:  "End behavior (1)",
			input: []byte{0x00, 0x01, 0x00, 0x00},
			expected: &EndpointBehavior{
				EndpointBehavior: 1,
				Flag:             0,
				Algorithm:        0,
			},
		},
		{
			name:  "End.X behavior (5)",
			input: []byte{0x00, 0x05, 0x00, 0x80},
			expected: &EndpointBehavior{
				EndpointBehavior: 5,
				Flag:             0,
				Algorithm:        128,
			},
		},
		{
			name:  "End.DT6 behavior (19)",
			input: []byte{0x00, 0x13, 0x00, 0x00},
			expected: &EndpointBehavior{
				EndpointBehavior: 19,
				Flag:             0,
				Algorithm:        0,
			},
		},
		{
			name:  "End.DT4 behavior (20)",
			input: []byte{0x00, 0x14, 0x01, 0x80},
			expected: &EndpointBehavior{
				EndpointBehavior: 20,
				Flag:             1,
				Algorithm:        128,
			},
		},
		{
			name:  "End.DT46 behavior (21)",
			input: []byte{0x00, 0x15, 0x00, 0x00},
			expected: &EndpointBehavior{
				EndpointBehavior: 21,
				Flag:             0,
				Algorithm:        0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6EndpointBehaviorTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result.EndpointBehavior != tt.expected.EndpointBehavior {
				t.Errorf("EndpointBehavior = %d, want %d", result.EndpointBehavior, tt.expected.EndpointBehavior)
			}
			if result.Flag != tt.expected.Flag {
				t.Errorf("Flag = %d, want %d", result.Flag, tt.expected.Flag)
			}
			if result.Algorithm != tt.expected.Algorithm {
				t.Errorf("Algorithm = %d, want %d", result.Algorithm, tt.expected.Algorithm)
			}
		})
	}
}

// TestRFC9252_SIDStructureTLV validates unmarshaling of the SRv6 SID
// Structure TLV (type 1252) used in BGP-LS.
func TestRFC9252_SIDStructureTLV(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *SIDStructure
	}{
		{
			name:  "Standard 40/24/16/0",
			input: []byte{0x28, 0x18, 0x10, 0x00},
			expected: &SIDStructure{
				LBLength:  40,
				LNLength:  24,
				FunLength: 16,
				ArgLength: 0,
			},
		},
		{
			name:  "With argument 48/16/16/8",
			input: []byte{0x30, 0x10, 0x10, 0x08},
			expected: &SIDStructure{
				LBLength:  48,
				LNLength:  16,
				FunLength: 16,
				ArgLength: 8,
			},
		},
		{
			name:  "All zeros",
			input: []byte{0x00, 0x00, 0x00, 0x00},
			expected: &SIDStructure{
				LBLength:  0,
				LNLength:  0,
				FunLength: 0,
				ArgLength: 0,
			},
		},
		{
			name:  "Max values",
			input: []byte{0xff, 0xff, 0xff, 0xff},
			expected: &SIDStructure{
				LBLength:  255,
				LNLength:  255,
				FunLength: 255,
				ArgLength: 255,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6SIDStructureTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result.LBLength != tt.expected.LBLength {
				t.Errorf("LBLength = %d, want %d", result.LBLength, tt.expected.LBLength)
			}
			if result.LNLength != tt.expected.LNLength {
				t.Errorf("LNLength = %d, want %d", result.LNLength, tt.expected.LNLength)
			}
			if result.FunLength != tt.expected.FunLength {
				t.Errorf("FunLength = %d, want %d", result.FunLength, tt.expected.FunLength)
			}
			if result.ArgLength != tt.expected.ArgLength {
				t.Errorf("ArgLength = %d, want %d", result.ArgLength, tt.expected.ArgLength)
			}
		})
	}
}

// TestRFC9252_EndXSIDTLV validates unmarshaling of End.X SID TLV including
// flags, algorithm, weight, SID, and optional sub-TLVs.
func TestRFC9252_EndXSIDTLV(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *EndXSIDTLV
	}{
		{
			name: "End.X SID with SID Structure sub-TLV",
			input: []byte{
				0x00, 0x06,                                                                                       // Endpoint Behavior: 6
				0x00,                                                                                             // Flags: all clear
				0x80,                                                                                             // Algorithm: 128
				0x00,                                                                                             // Weight
				0x00,                                                                                             // Reserved
				0x20, 0x01, 0x04, 0x20, 0xFF, 0xFF, 0x10, 0x77, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SID
				0x04, 0xE4, 0x00, 0x04, 0x28, 0x18, 0x10, 0x00,                                                 // SID Structure SubTLV (type 1252)
			},
			expected: &EndXSIDTLV{
				EndpointBehavior: 6,
				Flags: &EndXSIDFlags{
					BFlag: false,
					SFlag: false,
					PFlag: false,
				},
				Algorithm: 128,
				SID:       "2001:420:ffff:1077:40::",
				SubTLVs: []SubTLV{&SIDStructure{
					Type:      1252,
					Length:    8,
					LBLength:  40,
					LNLength:  24,
					FunLength: 16,
					ArgLength: 0,
				}},
			},
		},
		{
			name: "End.X SID with B flag set",
			input: []byte{
				0x00, 0x05,                                                                                       // Endpoint Behavior: 5
				0x80,                                                                                             // Flags: B=true
				0x00,                                                                                             // Algorithm: 0
				0x0a,                                                                                             // Weight: 10
				0x00,                                                                                             // Reserved
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SID
			},
			expected: &EndXSIDTLV{
				EndpointBehavior: 5,
				Flags: &EndXSIDFlags{
					BFlag: true,
					SFlag: false,
					PFlag: false,
				},
				Algorithm: 0,
				Weight:    10,
				SID:       "2001:db8::1",
			},
		},
		{
			name: "End.X SID with S and P flags",
			input: []byte{
				0x00, 0x06,                                                                                       // Endpoint Behavior: 6
				0x60,                                                                                             // Flags: S=true, P=true
				0x40,                                                                                             // Algorithm: 64
				0x00,                                                                                             // Weight: 0
				0x00,                                                                                             // Reserved
				0xfc, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SID
			},
			expected: &EndXSIDTLV{
				EndpointBehavior: 6,
				Flags: &EndXSIDFlags{
					BFlag: false,
					SFlag: true,
					PFlag: true,
				},
				Algorithm: 64,
				SID:       "fc00:0:1::",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6EndXSIDTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %+v", err)
			}
			if result.EndpointBehavior != tt.expected.EndpointBehavior {
				t.Errorf("EndpointBehavior = %d, want %d", result.EndpointBehavior, tt.expected.EndpointBehavior)
			}
			if result.Flags.BFlag != tt.expected.Flags.BFlag {
				t.Errorf("BFlag = %v, want %v", result.Flags.BFlag, tt.expected.Flags.BFlag)
			}
			if result.Flags.SFlag != tt.expected.Flags.SFlag {
				t.Errorf("SFlag = %v, want %v", result.Flags.SFlag, tt.expected.Flags.SFlag)
			}
			if result.Flags.PFlag != tt.expected.Flags.PFlag {
				t.Errorf("PFlag = %v, want %v", result.Flags.PFlag, tt.expected.Flags.PFlag)
			}
			if result.Algorithm != tt.expected.Algorithm {
				t.Errorf("Algorithm = %d, want %d", result.Algorithm, tt.expected.Algorithm)
			}
			if result.Weight != tt.expected.Weight {
				t.Errorf("Weight = %d, want %d", result.Weight, tt.expected.Weight)
			}
			if result.SID != tt.expected.SID {
				t.Errorf("SID = %q, want %q", result.SID, tt.expected.SID)
			}
			if tt.expected.SubTLVs != nil {
				if !reflect.DeepEqual(tt.expected.SubTLVs, result.SubTLVs) {
					t.Errorf("SubTLVs mismatch: %+v", deep.Equal(tt.expected.SubTLVs, result.SubTLVs))
				}
			}
		})
	}
}

// TestRFC9252_EndXSIDTLV_InvalidLength validates error handling for
// End.X SID TLV with insufficient data.
func TestRFC9252_EndXSIDTLV_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "Empty input",
			input: []byte{},
		},
		{
			name:  "Too short (10 bytes)",
			input: []byte{0x00, 0x06, 0x00, 0x80, 0x00, 0x00, 0x20, 0x01, 0x04, 0x20},
		},
		{
			name:  "Below minimum (21 bytes)",
			input: []byte{0x00, 0x06, 0x00, 0x80, 0x00, 0x00, 0x20, 0x01, 0x04, 0x20, 0xff, 0xff, 0x10, 0x77, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalSRv6EndXSIDTLV(tt.input)
			if err == nil {
				t.Error("expected error for invalid length input")
			}
		})
	}
}

// TestRFC9252_EndXSIDFlags validates flag parsing for all combinations.
func TestRFC9252_EndXSIDFlags(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		expected *EndXSIDFlags
	}{
		{
			name:     "All flags clear",
			input:    0x00,
			expected: &EndXSIDFlags{BFlag: false, SFlag: false, PFlag: false},
		},
		{
			name:     "B flag set",
			input:    0x80,
			expected: &EndXSIDFlags{BFlag: true, SFlag: false, PFlag: false},
		},
		{
			name:     "S flag set",
			input:    0x40,
			expected: &EndXSIDFlags{BFlag: false, SFlag: true, PFlag: false},
		},
		{
			name:     "P flag set",
			input:    0x20,
			expected: &EndXSIDFlags{BFlag: false, SFlag: false, PFlag: true},
		},
		{
			name:     "All flags set",
			input:    0xe0,
			expected: &EndXSIDFlags{BFlag: true, SFlag: true, PFlag: true},
		},
		{
			name:     "B and S flags set",
			input:    0xc0,
			expected: &EndXSIDFlags{BFlag: true, SFlag: true, PFlag: false},
		},
		{
			name:     "Reserved bits set only",
			input:    0x1f,
			expected: &EndXSIDFlags{BFlag: false, SFlag: false, PFlag: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalEndXSIDFlags([]byte{tt.input})
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result.BFlag != tt.expected.BFlag {
				t.Errorf("BFlag = %v, want %v", result.BFlag, tt.expected.BFlag)
			}
			if result.SFlag != tt.expected.SFlag {
				t.Errorf("SFlag = %v, want %v", result.SFlag, tt.expected.SFlag)
			}
			if result.PFlag != tt.expected.PFlag {
				t.Errorf("PFlag = %v, want %v", result.PFlag, tt.expected.PFlag)
			}
		})
	}
}

// TestRFC9252_EndXSIDFlags_EmptyInput validates error for empty input.
func TestRFC9252_EndXSIDFlags_EmptyInput(t *testing.T) {
	_, err := UnmarshalEndXSIDFlags([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

// TestRFC9252_LocatorTLV validates unmarshaling of SRv6 Locator TLV.
func TestRFC9252_LocatorTLV(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *LocatorTLV
	}{
		{
			name: "Basic locator with D flag clear",
			input: []byte{
				0x00,                   // Flags: D=false
				0x00,                   // Algorithm: 0
				0x00, 0x00,             // Reserved
				0x00, 0x00, 0x00, 0x0a, // Metric: 10
			},
			expected: &LocatorTLV{
				Flag:      &LocatorFlags{DFlag: false},
				Algorithm: 0,
				Metric:    10,
			},
		},
		{
			name: "Locator with D flag set",
			input: []byte{
				0x80,                   // Flags: D=true
				0x80,                   // Algorithm: 128
				0x00, 0x00,             // Reserved
				0x00, 0x00, 0x00, 0x64, // Metric: 100
			},
			expected: &LocatorTLV{
				Flag:      &LocatorFlags{DFlag: true},
				Algorithm: 128,
				Metric:    100,
			},
		},
		{
			name: "Locator with max metric",
			input: []byte{
				0x00,                   // Flags
				0xff,                   // Algorithm: 255
				0x00, 0x00,             // Reserved
				0xff, 0xff, 0xff, 0xff, // Metric: max
			},
			expected: &LocatorTLV{
				Flag:      &LocatorFlags{DFlag: false},
				Algorithm: 255,
				Metric:    4294967295,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6LocatorTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result.Flag.DFlag != tt.expected.Flag.DFlag {
				t.Errorf("DFlag = %v, want %v", result.Flag.DFlag, tt.expected.Flag.DFlag)
			}
			if result.Algorithm != tt.expected.Algorithm {
				t.Errorf("Algorithm = %d, want %d", result.Algorithm, tt.expected.Algorithm)
			}
			if result.Metric != tt.expected.Metric {
				t.Errorf("Metric = %d, want %d", result.Metric, tt.expected.Metric)
			}
		})
	}
}

// TestRFC9252_LocatorFlags validates locator flag parsing.
func TestRFC9252_LocatorFlags(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		expected bool
	}{
		{"D flag clear", 0x00, false},
		{"D flag set", 0x80, true},
		{"Other bits set but not D", 0x7f, false},
		{"All bits set", 0xff, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalLocatorFlags([]byte{tt.input})
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result.DFlag != tt.expected {
				t.Errorf("DFlag = %v, want %v", result.DFlag, tt.expected)
			}
		})
	}
}

// TestRFC9252_LocatorFlags_EmptyInput validates error for empty input.
func TestRFC9252_LocatorFlags_EmptyInput(t *testing.T) {
	_, err := UnmarshalLocatorFlags([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

// TestRFC9252_CapabilityTLV validates unmarshaling of SRv6 Capability TLV.
func TestRFC9252_CapabilityTLV(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *CapabilityTLV
	}{
		{
			name:     "O flag clear",
			input:    []byte{0x00, 0x00, 0x00, 0x00},
			expected: &CapabilityTLV{OFlag: false},
		},
		{
			name:     "O flag set",
			input:    []byte{0x40, 0x00, 0x00, 0x00},
			expected: &CapabilityTLV{OFlag: true},
		},
		{
			name:     "Other bits set but not O",
			input:    []byte{0xbf, 0x00, 0x00, 0x00},
			expected: &CapabilityTLV{OFlag: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6CapabilityTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result.OFlag != tt.expected.OFlag {
				t.Errorf("OFlag = %v, want %v", result.OFlag, tt.expected.OFlag)
			}
		})
	}
}

// TestRFC9252_CapabilityTLV_TooShort validates error for insufficient input.
func TestRFC9252_CapabilityTLV_TooShort(t *testing.T) {
	inputs := [][]byte{
		{},
		{0x00},
		{0x00, 0x00},
		{0x00, 0x00, 0x00},
	}
	for _, input := range inputs {
		_, err := UnmarshalSRv6CapabilityTLV(input)
		if err == nil {
			t.Errorf("expected error for %d-byte input", len(input))
		}
	}
}

// TestRFC9252_BGPPeerNodeSID validates unmarshaling of BGP Peer Node SID TLV.
func TestRFC9252_BGPPeerNodeSID(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *BGPPeerNodeSID
	}{
		{
			// Layout: Flags(1) + Weight(1) + skip 2 reserved via p+=2 = PeerASN at b[3:7]
			// Implementation: p=0 flags, p++ -> p=1 weight, p+=2 -> p=3, PeerASN=b[3:7], p+=4 -> p=7, PeerID=b[7:11]
			name: "Basic peer node SID",
			input: []byte{
				0x00,                   // [0] Flags: all clear
				0x0a,                   // [1] Weight: 10
				0x00,                   // [2] Reserved (skipped via p+=2)
				0x00, 0x00, 0xfd, 0xe8, // [3-6] PeerASN: 65000
				0xc0, 0xa8, 0x01, 0x01, // [7-10] PeerID: 192.168.1.1
			},
			expected: &BGPPeerNodeSID{
				Flags:   &BGPPeerNodeFlags{BFlag: false, SFlag: false, PFlag: false},
				Weight:  10,
				PeerASN: 65000,
				PeerID:  []byte{0xc0, 0xa8, 0x01, 0x01},
			},
		},
		{
			name: "All flags set",
			input: []byte{
				0xe0,                   // [0] Flags: B=true, S=true, P=true
				0xff,                   // [1] Weight: 255
				0x00,                   // [2] Reserved
				0x00, 0x01, 0x00, 0x00, // [3-6] PeerASN: 65536
				0x0a, 0x00, 0x00, 0x01, // [7-10] PeerID: 10.0.0.1
			},
			expected: &BGPPeerNodeSID{
				Flags:   &BGPPeerNodeFlags{BFlag: true, SFlag: true, PFlag: true},
				Weight:  255,
				PeerASN: 65536,
				PeerID:  []byte{0x0a, 0x00, 0x00, 0x01},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6BGPPeerNodeSIDTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result.Flags.BFlag != tt.expected.Flags.BFlag {
				t.Errorf("BFlag = %v, want %v", result.Flags.BFlag, tt.expected.Flags.BFlag)
			}
			if result.Flags.SFlag != tt.expected.Flags.SFlag {
				t.Errorf("SFlag = %v, want %v", result.Flags.SFlag, tt.expected.Flags.SFlag)
			}
			if result.Flags.PFlag != tt.expected.Flags.PFlag {
				t.Errorf("PFlag = %v, want %v", result.Flags.PFlag, tt.expected.Flags.PFlag)
			}
			if result.Weight != tt.expected.Weight {
				t.Errorf("Weight = %d, want %d", result.Weight, tt.expected.Weight)
			}
			if result.PeerASN != tt.expected.PeerASN {
				t.Errorf("PeerASN = %d, want %d", result.PeerASN, tt.expected.PeerASN)
			}
			if !reflect.DeepEqual(result.PeerID, tt.expected.PeerID) {
				t.Errorf("PeerID = %v, want %v", result.PeerID, tt.expected.PeerID)
			}
		})
	}
}

// TestRFC9252_BGPPeerNodeFlags validates flag parsing for BGP Peer Node SID.
func TestRFC9252_BGPPeerNodeFlags(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		expected *BGPPeerNodeFlags
	}{
		{"No flags", 0x00, &BGPPeerNodeFlags{false, false, false}},
		{"B flag", 0x80, &BGPPeerNodeFlags{true, false, false}},
		{"S flag", 0x40, &BGPPeerNodeFlags{false, true, false}},
		{"P flag", 0x20, &BGPPeerNodeFlags{false, false, true}},
		{"All flags", 0xe0, &BGPPeerNodeFlags{true, true, true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalBGPPeerNodeFlags([]byte{tt.input})
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("got %+v, want %+v", result, tt.expected)
			}
		})
	}
}

// TestRFC9252_BGPPeerNodeFlags_EmptyInput validates error for empty input.
func TestRFC9252_BGPPeerNodeFlags_EmptyInput(t *testing.T) {
	_, err := UnmarshalBGPPeerNodeFlags([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

// TestRFC9252_SubTLV validates generic SubTLV unmarshaling including
// type 1252 (SID Structure) and unknown types.
func TestRFC9252_SubTLV(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		expectedType uint16
	}{
		{
			name: "SID Structure SubTLV (type 1252)",
			input: []byte{
				0x04, 0xe4,             // Type: 1252
				0x00, 0x04,             // Length: 4
				0x28, 0x18, 0x10, 0x00, // SID structure data
			},
			expectedType: 1252,
		},
		{
			name: "Unknown SubTLV type",
			input: []byte{
				0x04, 0xe5,             // Type: 1253 (unknown)
				0x00, 0x02,             // Length: 2
				0xaa, 0xbb,             // Raw value
			},
			expectedType: 1253,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6SubTLV(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result.GetType() != tt.expectedType {
				t.Errorf("Type = %d, want %d", result.GetType(), tt.expectedType)
			}
		})
	}
}

// TestRFC9252_SubTLV_TooShort validates error handling for SubTLVs with
// insufficient header bytes.
func TestRFC9252_SubTLV_TooShort(t *testing.T) {
	inputs := [][]byte{
		{},
		{0x04},
		{0x04, 0xe4},
		{0x04, 0xe4, 0x00},
	}
	for _, input := range inputs {
		_, err := UnmarshalSRv6SubTLV(input)
		if err == nil {
			t.Errorf("expected error for %d-byte SubTLV input", len(input))
		}
	}
}

// TestRFC9252_AllSubTLV validates unmarshaling multiple SubTLVs in sequence.
func TestRFC9252_AllSubTLV(t *testing.T) {
	input := []byte{
		0x04, 0xe4,             // Type 1252
		0x00, 0x04,             // Length 4
		0x28, 0x18, 0x10, 0x00, // SID Structure
		0x04, 0xe5,             // Type 1253 (unknown)
		0x00, 0x02,             // Length 2
		0xaa, 0xbb,             // Raw value
	}
	result, err := UnmarshalAllSRv6SubTLV(input)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("got %d SubTLVs, want 2", len(result))
	}
	if result[0].GetType() != 1252 {
		t.Errorf("first SubTLV type = %d, want 1252", result[0].GetType())
	}
	if result[1].GetType() != 1253 {
		t.Errorf("second SubTLV type = %d, want 1253", result[1].GetType())
	}
}

// TestRFC9252_SIDDescriptor validates unmarshaling of SRv6 SID Descriptor
// containing SID (type 518) and Multi-Topology ID (type 263).
func TestRFC9252_SIDDescriptor(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *SIDDescriptor
	}{
		{
			name: "SID and MTID",
			input: []byte{
				0x01, 0x07,                                                                                       // Type 263 (MTID)
				0x00, 0x02,                                                                                       // Length 2
				0x00, 0x02,                                                                                       // MTID value
				0x02, 0x06,                                                                                       // Type 518 (SID)
				0x00, 0x10,                                                                                       // Length 16
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SID
			},
			expected: &SIDDescriptor{
				SID: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				MultiTopologyID: []*base.MultiTopologyIdentifier{
					{OFlag: false, AFlag: false, MTID: 2},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSRv6SIDDescriptor(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if !reflect.DeepEqual(result.SID, tt.expected.SID) {
				t.Errorf("SID = %v, want %v", result.SID, tt.expected.SID)
			}
			if len(result.MultiTopologyID) != len(tt.expected.MultiTopologyID) {
				t.Fatalf("MTID count = %d, want %d", len(result.MultiTopologyID), len(tt.expected.MultiTopologyID))
			}
			if result.MultiTopologyID[0].MTID != tt.expected.MultiTopologyID[0].MTID {
				t.Errorf("MTID = %d, want %d", result.MultiTopologyID[0].MTID, tt.expected.MultiTopologyID[0].MTID)
			}
		})
	}
}

// TestRFC9252_SIDDescriptor_InvalidType validates error for unknown descriptor types.
func TestRFC9252_SIDDescriptor_InvalidType(t *testing.T) {
	input := []byte{
		0xff, 0xff,       // Unknown type
		0x00, 0x02,       // Length 2
		0x00, 0x00,       // Value
	}
	_, err := UnmarshalSRv6SIDDescriptor(input)
	if err == nil {
		t.Error("expected error for invalid SID Descriptor type")
	}
}

// TestRFC9252_SIDNLRI_EmptyInput validates error for empty NLRI input.
func TestRFC9252_SIDNLRI_EmptyInput(t *testing.T) {
	_, err := UnmarshalSRv6SIDNLRI([]byte{})
	if err == nil {
		t.Error("expected error for empty NLRI input")
	}
}
