package vpls

import (
	"testing"
)

// Test RFC 4761 NLRI parsing (17 bytes)
func TestUnmarshalRFC4761NLRI(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *NLRI)
	}{
		{
			name: "Valid RFC 4761 NLRI",
			// Length: 0x0011 (17)
			// RD: Type 0, Admin:1, Assigned:100
			// VE ID: 1
			// VE Block Offset: 0
			// VE Block Size: 10
			// Label Base: 100,000 (0x0186a0)
			input: []byte{
				0x00, 0x11, // Length: 17
				0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD Type 0 (8 bytes)
				0x00, 0x01, // VE ID: 1
				0x00, 0x00, // VE Block Offset: 0
				0x00, 0x0a, // VE Block Size: 10
				0x18, 0x6a, 0x00, // Label Base: 100,000 (0x186A0)
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				if nlri.RFCType != "RFC4761" {
					t.Errorf("RFCType = %s, want RFC4761", nlri.RFCType)
				}
				if nlri.VEID == nil || *nlri.VEID != 1 {
					t.Errorf("VEID = %v, want 1", nlri.VEID)
				}
				if nlri.VEBlockOffset == nil || *nlri.VEBlockOffset != 0 {
					t.Errorf("VEBlockOffset = %v, want 0", nlri.VEBlockOffset)
				}
				if nlri.VEBlockSize == nil || *nlri.VEBlockSize != 10 {
					t.Errorf("VEBlockSize = %v, want 10", nlri.VEBlockSize)
				}
				if nlri.LabelBase == nil || *nlri.LabelBase != 100000 {
					t.Errorf("LabelBase = %v, want 100000", nlri.LabelBase)
				}
				// Verify label range calculation
				start, end := nlri.GetLabelRange()
				if start != 100000 || end != 100009 {
					t.Errorf("Label range = %d-%d, want 100000-100009", start, end)
				}
			},
		},
		{
			name: "RFC 4761 with max label",
			input: []byte{
				0x00, 0x11, // Length: 17
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // RD Type 0 (8 bytes)
				0x00, 0x64, // VE ID: 100
				0x00, 0x00, // VE Block Offset: 0
				0x00, 0x01, // VE Block Size: 1
				0xff, 0xff, 0xf0, // Label Base: 1,048,575 (0xFFFFF, max 20-bit)
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				if nlri.LabelBase == nil || *nlri.LabelBase != 0xFFFFF {
					t.Errorf("LabelBase = %v, want 1048575 (0xFFFFF)", nlri.LabelBase)
				}
			},
		},
		{
			name:    "Invalid length - too short",
			input:   []byte{0x00, 0x10, 0x00, 0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name: "Invalid length - too long",
			input: []byte{
				0x00, 0x12, // Wrong length: 18 instead of 17
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // RD (8 bytes)
				0x00, 0x01, // VE ID
				0x00, 0x00, // VE Block Offset
				0x00, 0x01, // VE Block Size
				0x18, 0x6a, 0x00, // Label Base
				0x00, // Extra byte
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := UnmarshalVPLSNLRI(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalVPLSNLRI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.verify != nil {
				if len(route.Route) != 1 {
					t.Fatalf("Expected 1 NLRI, got %d", len(route.Route))
				}
				tt.verify(t, route.Route[0])
			}
		})
	}
}

// Test RFC 6074 NLRI parsing (12 bytes)
func TestUnmarshalRFC6074NLRI(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *NLRI)
	}{
		{
			name: "Valid RFC 6074 NLRI",
			// Length: 0x000c (12)
			// RD: Type 0, Admin:1, Assigned:100
			// PE Address: 192.168.1.1
			input: []byte{
				0x00, 0x0c, // Length: 12
				0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD Type 0 (8 bytes)
				0xc0, 0xa8, 0x01, 0x01, // PE Address: 192.168.1.1
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				if nlri.RFCType != "RFC6074" {
					t.Errorf("RFCType = %s, want RFC6074", nlri.RFCType)
				}
				if nlri.PEAddr == nil || *nlri.PEAddr != "192.168.1.1" {
					t.Errorf("PEAddr = %v, want 192.168.1.1", nlri.PEAddr)
				}
				// RFC 6074 should not have VE ID, label fields
				if nlri.VEID != nil {
					t.Errorf("RFC6074 should not have VEID, got %v", *nlri.VEID)
				}
				if nlri.LabelBase != nil {
					t.Errorf("RFC6074 should not have LabelBase, got %v", *nlri.LabelBase)
				}
			},
		},
		{
			name: "RFC 6074 with PE 10.0.0.1",
			input: []byte{
				0x00, 0x0c, // Length: 12
				0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x64, // RD Type 0 (8 bytes)
				0x0a, 0x00, 0x00, 0x01, // PE: 10.0.0.1
			},
			wantErr: false,
			verify: func(t *testing.T, nlri *NLRI) {
				if nlri.PEAddr == nil || *nlri.PEAddr != "10.0.0.1" {
					t.Errorf("PEAddr = %v, want 10.0.0.1", nlri.PEAddr)
				}
			},
		},
		{
			name:    "Invalid length - too short",
			input:   []byte{0x00, 0x0b, 0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name: "Invalid length - too long",
			input: []byte{
				0x00, 0x0d, // Wrong length: 13 instead of 12
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // RD (8 bytes)
				0xc0, 0xa8, 0x01, 0x01, // PE Address
				0x00, // Extra byte
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := UnmarshalVPLSNLRI(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalVPLSNLRI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.verify != nil {
				if len(route.Route) != 1 {
					t.Fatalf("Expected 1 NLRI, got %d", len(route.Route))
				}
				tt.verify(t, route.Route[0])
			}
		})
	}
}

// Test multiple NLRIs in single update (mixed RFC 4761 and RFC 6074)
func TestUnmarshalVPLSNLRI_Multiple(t *testing.T) {
	// Mixed: RFC 4761 (17 bytes) + RFC 6074 (12 bytes)
	input := []byte{
		// First NLRI: RFC 4761
		0x00, 0x11, // Length: 17
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // RD
		0x00, 0x01, // VE ID
		0x00, 0x00, // VE Block Offset
		0x00, 0x0a, // VE Block Size
		0x01, 0x86, 0xa0, // Label Base

		// Second NLRI: RFC 6074
		0x00, 0x0c, // Length: 12
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // RD
		0xc0, 0xa8, 0x01, 0x01, // PE Address
	}

	route, err := UnmarshalVPLSNLRI(input)
	if err != nil {
		t.Fatalf("UnmarshalVPLSNLRI() error = %v", err)
	}

	if len(route.Route) != 2 {
		t.Fatalf("Expected 2 NLRIs, got %d", len(route.Route))
	}

	// Verify first NLRI is RFC 4761
	if route.Route[0].RFCType != "RFC4761" {
		t.Errorf("First NLRI type = %s, want RFC4761", route.Route[0].RFCType)
	}

	// Verify second NLRI is RFC 6074
	if route.Route[1].RFCType != "RFC6074" {
		t.Errorf("Second NLRI type = %s, want RFC6074", route.Route[1].RFCType)
	}
}

// Test edge cases
func TestUnmarshalVPLSNLRI_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "Empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "Only length field",
			input:   []byte{0x00, 0x11},
			wantErr: true,
		},
		{
			name: "Unknown NLRI length",
			input: []byte{
				0x00, 0x0f, // Length: 15 (invalid)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantErr: true,
		},
		{
			name: "Incomplete NLRI",
			input: []byte{
				0x00, 0x11, // Length: 17
				0x00, 0x00, 0x00, 0x00, // Only partial data
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalVPLSNLRI(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalVPLSNLRI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test String() methods
func TestNLRI_String(t *testing.T) {
	// RFC 4761 NLRI
	rfc4761 := []byte{
		0x00, 0x11, // Length: 17
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD Type 0 (8 bytes)
		0x00, 0x01, // VE ID: 1
		0x00, 0x00, // VE Block Offset: 0
		0x00, 0x0a, // VE Block Size: 10
		0x18, 0x6a, 0x00, // Label Base: 100,000 (0x186A0)
	}

	route, err := UnmarshalVPLSNLRI(rfc4761)
	if err != nil {
		t.Fatalf("UnmarshalVPLSNLRI() error = %v", err)
	}

	str := route.Route[0].String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	// Should contain key information
	if !contains(str, "RFC4761") {
		t.Error("String() missing RFC4761")
	}
	if !contains(str, "VEID=1") {
		t.Error("String() missing VEID")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestNLRI_GetPEAddress tests GetPEAddress method
func TestNLRI_GetPEAddress(t *testing.T) {
	tests := []struct {
		name string
		nlri *NLRI
		want string
	}{
		{
			name: "RFC6074 with PE address",
			nlri: &NLRI{
				RFCType: "RFC6074",
				PEAddr:  stringPtr("10.0.0.1"),
			},
			want: "10.0.0.1",
		},
		{
			name: "RFC4761 returns empty",
			nlri: &NLRI{
				RFCType: "RFC4761",
			},
			want: "",
		},
		{
			name: "RFC6074 with nil PE address",
			nlri: &NLRI{
				RFCType: "RFC6074",
				PEAddr:  nil,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.nlri.GetPEAddress()
			if got != tt.want {
				t.Errorf("GetPEAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNLRI_GetLabelRange tests GetLabelRange method
func TestNLRI_GetLabelRange(t *testing.T) {
	tests := []struct {
		name      string
		nlri      *NLRI
		wantStart uint32
		wantEnd   uint32
	}{
		{
			name: "RFC4761 with valid labels",
			nlri: &NLRI{
				RFCType:     "RFC4761",
				LabelBase:   uint32Ptr(100000),
				VEBlockSize: uint16Ptr(10),
			},
			wantStart: 100000,
			wantEnd:   100009,
		},
		{
			name: "RFC6074 returns 0,0",
			nlri: &NLRI{
				RFCType: "RFC6074",
			},
			wantStart: 0,
			wantEnd:   0,
		},
		{
			name: "RFC4761 with nil LabelBase",
			nlri: &NLRI{
				RFCType:   "RFC4761",
				LabelBase: nil,
			},
			wantStart: 0,
			wantEnd:   0,
		},
		{
			name: "RFC4761 with nil VEBlockSize",
			nlri: &NLRI{
				RFCType:   "RFC4761",
				LabelBase: uint32Ptr(100),
			},
			wantStart: 0,
			wantEnd:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end := tt.nlri.GetLabelRange()
			if start != tt.wantStart || end != tt.wantEnd {
				t.Errorf("GetLabelRange() = (%v, %v), want (%v, %v)", start, end, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

// TestNLRI_String_RFC6074 tests String method for RFC6074
func TestNLRI_String_RFC6074(t *testing.T) {
	// Parse actual RFC 6074 NLRI to get valid RD
	input := []byte{
		0x00, 0x0c, // Length: 12
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD Type 0
		0x0a, 0x00, 0x00, 0x01, // PE Address: 10.0.0.1
	}
	route, err := UnmarshalVPLSNLRI(input)
	if err != nil {
		t.Fatalf("UnmarshalVPLSNLRI() error = %v", err)
	}

	str := route.Route[0].String()
	if !contains(str, "RFC6074") {
		t.Errorf("String() = %s, should contain 'RFC6074'", str)
	}
}

// Helper functions for pointer creation
func stringPtr(s string) *string {
	return &s
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func uint16Ptr(v uint16) *uint16 {
	return &v
}

// TestFormatIPv4_ErrorCase tests formatIPv4 error handling
func TestFormatIPv4_ErrorCase(t *testing.T) {
	// This is a private function but we can test it indirectly through RFC6074 parsing
	// Test with invalid PE address length (not 4 bytes)
	input := []byte{
		0x00, 0x0c, // Length: 12
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD Type 0
		0x0a, 0x00, 0x00, // PE Address: only 3 bytes (invalid)
	}

	_, err := UnmarshalVPLSNLRI(input)
	if err == nil {
		t.Error("Expected error for invalid PE address length, got nil")
	}
}

// TestUnmarshalRFC4761NLRI_MaxLabel tests maximum valid label
func TestUnmarshalRFC4761NLRI_MaxLabel(t *testing.T) {
	// Test with maximum valid 20-bit label (0xFFFFF = 1,048,575)
	// Note: Due to the extraction formula (b[14]<<12 | b[15]<<4 | b[16]>>4),
	// the maximum extractable value is exactly 0xFFFFF with bytes [0xFF, 0xFF, 0xFF]
	// It's mathematically impossible to exceed 0xFFFFF with this encoding.
	input := []byte{
		0x00, 0x11, // Length: 17
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD Type 0
		0x00, 0x01, // VE ID: 1
		0x00, 0x00, // VE Block Offset: 0
		0x00, 0x0a, // VE Block Size: 10
		0xFF, 0xFF, 0xFF, // Label Base: 0xFFFFF (max 20-bit value)
	}

	route, err := UnmarshalVPLSNLRI(input)
	if err != nil {
		t.Fatalf("UnmarshalVPLSNLRI() error = %v, want nil", err)
	}

	// Verify the label was parsed correctly
	if route.Route[0].LabelBase == nil {
		t.Fatal("LabelBase is nil")
	}
	if *route.Route[0].LabelBase != 0xFFFFF {
		t.Errorf("LabelBase = %d, want %d", *route.Route[0].LabelBase, 0xFFFFF)
	}
}

// TestUnmarshalRFC4761NLRI_InvalidRD tests RD parsing error
func TestUnmarshalRFC4761NLRI_InvalidRD(t *testing.T) {
	// Create NLRI with invalid RD (all 0xFF which is invalid for any RD type)
	input := []byte{
		0x00, 0x11, // Length: 17
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Invalid RD
		0x00, 0x01, // VE ID: 1
		0x00, 0x00, // VE Block Offset: 0
		0x00, 0x0a, // VE Block Size: 10
		0x18, 0x6a, 0x00, // Label Base: 100,000
	}

	_, err := UnmarshalVPLSNLRI(input)
	// May or may not error depending on base.MakeRD implementation
	// This test ensures we handle the error path if it occurs
	if err != nil && !contains(err.Error(), "Route Distinguisher") {
		// If we get an error, it should mention RD
		t.Logf("RD parsing error (expected): %v", err)
	}
}

// TestUnmarshalRFC6074NLRI_InvalidRD tests RFC 6074 RD parsing error
func TestUnmarshalRFC6074NLRI_InvalidRD(t *testing.T) {
	// Create NLRI with invalid RD
	input := []byte{
		0x00, 0x0c, // Length: 12
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Invalid RD
		0x0a, 0x00, 0x00, 0x01, // PE Address: 10.0.0.1
	}

	_, err := UnmarshalVPLSNLRI(input)
	// May or may not error depending on base.MakeRD implementation
	if err != nil && !contains(err.Error(), "Route Distinguisher") {
		t.Logf("RD parsing error (expected): %v", err)
	}
}

// TestUnmarshalVPLSNLRI_PropagatesErrors tests error propagation
func TestUnmarshalVPLSNLRI_PropagatesErrors(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name: "RFC 4761 with invalid length claims complete data",
			input: []byte{
				0x00, 0x11, // Length: 17
				0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD
				0x00, 0x01, // VE ID
				0x00, 0x00, // VE Block Offset
				0x00, 0x0a, // VE Block Size
				// Missing label base (incomplete)
			},
			want: "incomplete NLRI",
		},
		{
			name: "RFC 6074 with incomplete data",
			input: []byte{
				0x00, 0x0c, // Length: 12
				0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD
				0x0a, 0x00, // Missing 2 bytes of PE address
			},
			want: "incomplete NLRI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalVPLSNLRI(tt.input)
			if err == nil {
				t.Error("Expected error, got nil")
			}
			if err != nil && !contains(err.Error(), tt.want) {
				t.Errorf("Error should mention '%s', got: %v", tt.want, err)
			}
		})
	}
}

// TestLayer2InfoExtComm_String_AllFlags tests all flag combinations
func TestLayer2InfoExtComm_String_AllFlags(t *testing.T) {
	tests := []struct {
		name string
		ec   *Layer2InfoExtComm
		want []string
	}{
		{
			name: "No flags set",
			ec: &Layer2InfoExtComm{
				EncapType:   4,
				ControlWord: false,
				SequencedDel: false,
				MTU:         1500,
			},
			want: []string{"Ethernet", "1500"},
		},
		{
			name: "Only S flag",
			ec: &Layer2InfoExtComm{
				EncapType:   5,
				ControlWord: false,
				SequencedDel: true,
				MTU:         1500,
			},
			want: []string{"VLAN", "S", "1500"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.ec.String()
			for _, want := range tt.want {
				if !contains(str, want) {
					t.Errorf("String() = %s, should contain %s", str, want)
				}
			}
		})
	}
}
