package srpolicy

import (
	"encoding/json"
	"testing"
)

// ============================================================================
// Type B Segment Tests (SRv6 SID)
// ============================================================================

func TestUnmarshalTypeBSegment_Valid(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantSID []byte
	}{
		{
			name: "Standard SRv6 SID",
			input: []byte{
				0x00, // Flags
				0x00, // Reserved
				// SRv6 SID (16 bytes)
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantSID: []byte{
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
		},
		{
			name: "All zeros SRv6 SID",
			input: []byte{
				0x00, 0x00, // Flags, Reserved
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			wantSID: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "All ones SRv6 SID",
			input: []byte{
				0xFF, 0x00, // Flags (all set), Reserved
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			wantSID: []byte{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := UnmarshalTypeBSegment(tt.input)
			if err != nil {
				t.Errorf("UnmarshalTypeBSegment() error = %v", err)
				return
			}

			typeBSeg, ok := seg.(TypeBSegment)
			if !ok {
				t.Error("Segment is not TypeBSegment")
				return
			}

			sid := typeBSeg.GetSRv6SID()
			if len(sid) != 16 {
				t.Errorf("SRv6 SID length = %d, want 16", len(sid))
				return
			}

			for i, b := range tt.wantSID {
				if sid[i] != b {
					t.Errorf("SRv6 SID byte %d = %02x, want %02x", i, sid[i], b)
				}
			}

			if seg.GetType() != TypeB {
				t.Errorf("GetType() = %v, want TypeB", seg.GetType())
			}
		})
	}
}

func TestUnmarshalTypeBSegment_InvalidLength(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		length int
	}{
		{
			name:   "Too short - 17 bytes",
			input:  make([]byte, 17),
			length: 17,
		},
		{
			name:   "Too short - 10 bytes",
			input:  make([]byte, 10),
			length: 10,
		},
		{
			name:   "Too long - 19 bytes",
			input:  make([]byte, 19),
			length: 19,
		},
		{
			name:   "Too long - 20 bytes",
			input:  make([]byte, 20),
			length: 20,
		},
		{
			name:   "Empty",
			input:  []byte{},
			length: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalTypeBSegment(tt.input)
			if err == nil {
				t.Errorf("UnmarshalTypeBSegment() expected error for length %d, got nil", tt.length)
			}
		})
	}
}

func TestTypeBSegment_JSON(t *testing.T) {
	tests := []struct {
		name  string
		flags uint8
		sid   []byte
	}{
		{
			name:  "Standard SRv6 SID with no flags",
			flags: 0x00,
			sid: []byte{
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
		},
		{
			name:  "All zeros SID",
			flags: 0x00,
			sid:   make([]byte, 16),
		},
		{
			name:  "All flags set (V=0x80, A=0x40, S=0x20, B=0x10)",
			flags: 0xF0,
			sid: []byte{
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			},
		},
		{
			name:  "Only V-flag set",
			flags: 0x80,
			sid: []byte{
				0xfc, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg := &typeBSegment{
				flags: NewSegmentFlags(tt.flags),
				sid:   tt.sid,
			}

			// Marshal
			data, err := json.Marshal(seg)
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}

			// Unmarshal
			var result typeBSegment
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Verify all flags preserved
			if result.flags.Vflag != seg.flags.Vflag {
				t.Errorf("Unmarshal() Vflag = %v, want %v", result.flags.Vflag, seg.flags.Vflag)
			}
			if result.flags.Aflag != seg.flags.Aflag {
				t.Errorf("Unmarshal() Aflag = %v, want %v", result.flags.Aflag, seg.flags.Aflag)
			}
			if result.flags.Sflag != seg.flags.Sflag {
				t.Errorf("Unmarshal() Sflag = %v, want %v", result.flags.Sflag, seg.flags.Sflag)
			}
			if result.flags.Bflag != seg.flags.Bflag {
				t.Errorf("Unmarshal() Bflag = %v, want %v", result.flags.Bflag, seg.flags.Bflag)
			}

			// Verify SID length and content
			if len(result.sid) != 16 {
				t.Errorf("Unmarshal() SID length = %d, want 16", len(result.sid))
				return
			}

			for i, b := range tt.sid {
				if result.sid[i] != b {
					t.Errorf("Unmarshal() SID byte %d = %02x, want %02x", i, result.sid[i], b)
				}
			}
		})
	}
}

func TestUnmarshalSegmentListSTLV_TypeB(t *testing.T) {
	// Type B segment in SegmentList
	input := []byte{
		0x0D, // Type: Type B (13)
		0x12, // Length: 18 bytes
		0x00, // Flags
		0x00, // Reserved
		// SRv6 SID (16 bytes)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	sl, err := UnmarshalSegmentListSTLV(input)
	if err != nil {
		t.Errorf("UnmarshalSegmentListSTLV() error = %v", err)
		return
	}

	if len(sl.Segment) != 1 {
		t.Errorf("Expected 1 segment, got %d", len(sl.Segment))
		return
	}

	typeBSeg, ok := sl.Segment[0].(TypeBSegment)
	if !ok {
		t.Error("Segment is not TypeBSegment")
		return
	}

	sid := typeBSeg.GetSRv6SID()
	if len(sid) != 16 {
		t.Errorf("SRv6 SID length = %d, want 16", len(sid))
		return
	}

	// Verify actual SID value matches expected (2001:db8::1)
	expectedSID := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	for i, b := range expectedSID {
		if sid[i] != b {
			t.Errorf("SID byte %d = %02x, want %02x", i, sid[i], b)
		}
	}
}

// TestSegmentList_JSON_TypeB tests SegmentList JSON marshal/unmarshal with Type B segments.
// This test ensures SegmentList.UnmarshalJSON properly handles Type B segments.
func TestSegmentList_JSON_TypeB(t *testing.T) {
	// Create a SegmentList with a Type B segment
	originalSID := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	sl := &SegmentList{
		Weight: &Weight{Flags: 0, Weight: 100},
		Segment: []Segment{
			&typeBSegment{
				flags: NewSegmentFlags(0x80), // V-flag set
				sid:   originalSID,
			},
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(sl)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal from JSON
	var result SegmentList
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Verify Weight
	if result.Weight == nil {
		t.Fatal("Unmarshal() Weight is nil")
	}
	if result.Weight.Weight != 100 {
		t.Errorf("Unmarshal() Weight = %d, want 100", result.Weight.Weight)
	}

	// Verify Segments
	if len(result.Segment) != 1 {
		t.Fatalf("Unmarshal() segment count = %d, want 1", len(result.Segment))
	}

	// Verify Type B segment
	seg := result.Segment[0]
	if seg.GetType() != TypeB {
		t.Errorf("Unmarshal() segment type = %v, want TypeB", seg.GetType())
	}

	typeBSeg, ok := seg.(TypeBSegment)
	if !ok {
		t.Fatal("Unmarshal() segment is not TypeBSegment")
	}

	// Verify SID content
	sid := typeBSeg.GetSRv6SID()
	if len(sid) != 16 {
		t.Errorf("Unmarshal() SID length = %d, want 16", len(sid))
	}
	for i, b := range originalSID {
		if sid[i] != b {
			t.Errorf("Unmarshal() SID byte %d = %02x, want %02x", i, sid[i], b)
		}
	}

	// Verify flags preserved
	flags := seg.GetFlags()
	if flags == nil {
		t.Fatal("Unmarshal() flags is nil")
	}
	if !flags.Vflag {
		t.Error("Unmarshal() V-flag not preserved")
	}
}

// TestUnmarshalSegmentListSTLV_TypeB_Truncated tests error handling for truncated Type B wire data
func TestUnmarshalSegmentListSTLV_TypeB_Truncated(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name: "Only type and length, no payload",
			input: []byte{
				0x0D, // Type: Type B (13)
				0x12, // Length: 18 bytes
				// Missing 18 bytes of payload
			},
		},
		{
			name: "Partial payload (4 bytes instead of 18)",
			input: []byte{
				0x0D, // Type: Type B (13)
				0x12, // Length: 18 bytes
				0x00, 0x00, 0x00, 0x00, // Only 4 bytes
			},
		},
		{
			name: "Almost complete (17 bytes instead of 18)",
			input: []byte{
				0x0D, // Type: Type B (13)
				0x12, // Length: 18 bytes
				0x00, 0x00, // Flags, Reserved
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Missing last byte
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalSegmentListSTLV(tt.input)
			if err == nil {
				t.Error("Expected error for truncated input, got nil")
			}
		})
	}
}

// TestUnmarshalSegmentListSTLV_MultipleTypeB tests wire format parsing with multiple Type B segments
func TestUnmarshalSegmentListSTLV_MultipleTypeB(t *testing.T) {
	// Two Type B segments in SegmentList
	input := []byte{
		// First Type B segment
		0x0D,       // Type: Type B (13)
		0x12,       // Length: 18 bytes
		0x80,       // Flags (V-flag set)
		0x00,       // Reserved
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // SRv6 SID: 2001:db8::1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		// Second Type B segment
		0x0D,       // Type: Type B (13)
		0x12,       // Length: 18 bytes
		0x00,       // Flags (none set)
		0x00,       // Reserved
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // SRv6 SID: 2001:db8::2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}

	sl, err := UnmarshalSegmentListSTLV(input)
	if err != nil {
		t.Fatalf("UnmarshalSegmentListSTLV() error = %v", err)
	}

	if len(sl.Segment) != 2 {
		t.Fatalf("Expected 2 segments, got %d", len(sl.Segment))
	}

	// Verify first segment
	seg1, ok := sl.Segment[0].(TypeBSegment)
	if !ok {
		t.Fatal("First segment is not TypeBSegment")
	}
	sid1 := seg1.GetSRv6SID()
	if sid1[15] != 0x01 {
		t.Errorf("First segment SID last byte = %02x, want 0x01", sid1[15])
	}
	if !sl.Segment[0].GetFlags().Vflag {
		t.Error("First segment V-flag not set")
	}

	// Verify second segment
	seg2, ok := sl.Segment[1].(TypeBSegment)
	if !ok {
		t.Fatal("Second segment is not TypeBSegment")
	}
	sid2 := seg2.GetSRv6SID()
	if sid2[15] != 0x02 {
		t.Errorf("Second segment SID last byte = %02x, want 0x02", sid2[15])
	}
	if sl.Segment[1].GetFlags().Vflag {
		t.Error("Second segment V-flag should not be set")
	}
}

// TestSegmentList_JSON_MultipleTypeB tests JSON round-trip with multiple Type B segments
func TestSegmentList_JSON_MultipleTypeB(t *testing.T) {
	sid1 := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	sid2 := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}

	sl := &SegmentList{
		Weight: &Weight{Flags: 0, Weight: 50},
		Segment: []Segment{
			&typeBSegment{flags: NewSegmentFlags(0x80), sid: sid1},
			&typeBSegment{flags: NewSegmentFlags(0x00), sid: sid2},
		},
	}

	// Marshal
	data, err := json.Marshal(sl)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal
	var result SegmentList
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Verify segment count
	if len(result.Segment) != 2 {
		t.Fatalf("Expected 2 segments, got %d", len(result.Segment))
	}

	// Verify both segments are Type B with correct SIDs
	for i, expectedSID := range [][]byte{sid1, sid2} {
		seg, ok := result.Segment[i].(TypeBSegment)
		if !ok {
			t.Fatalf("Segment %d is not TypeBSegment", i)
		}
		sid := seg.GetSRv6SID()
		if sid[15] != expectedSID[15] {
			t.Errorf("Segment %d SID last byte = %02x, want %02x", i, sid[15], expectedSID[15])
		}
	}
}

// ============================================================================
// Type C Segment Tests (IPv4 + SR Algorithm + optional SID)
// ============================================================================

func TestUnmarshalTypeCSegment_Valid(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantIPv4    []byte
		wantAlgo    byte
		wantSID     *uint32
	}{
		{
			name: "Without SID (6 bytes)",
			input: []byte{
				0x00, // Flags
				0x00, // SR Algorithm
				192, 168, 1, 1, // IPv4: 192.168.1.1
			},
			wantIPv4: []byte{192, 168, 1, 1},
			wantAlgo: 0x00,
			wantSID:  nil,
		},
		{
			name: "With SID (10 bytes)",
			input: []byte{
				0x80, // Flags (V flag set)
				0x01, // SR Algorithm
				10, 0, 0, 1, // IPv4: 10.0.0.1
				0x00, 0x00, 0x03, 0xE8, // SID: 1000
			},
			wantIPv4: []byte{10, 0, 0, 1},
			wantAlgo: 0x01,
			wantSID:  ptrUint32(1000),
		},
		{
			name: "All zeros without SID",
			input: []byte{
				0x00, 0x00, // Flags, SR Algorithm
				0x00, 0x00, 0x00, 0x00, // IPv4
			},
			wantIPv4: []byte{0, 0, 0, 0},
			wantAlgo: 0x00,
			wantSID:  nil,
		},
		{
			name: "With SID = 0 (edge case)",
			input: []byte{
				0x00, // Flags
				0x00, // SR Algorithm
				192, 168, 1, 1, // IPv4: 192.168.1.1
				0x00, 0x00, 0x00, 0x00, // SID: 0
			},
			wantIPv4: []byte{192, 168, 1, 1},
			wantAlgo: 0x00,
			wantSID:  ptrUint32(0),
		},
		{
			name: "With SID = 0xFFFFFFFF (max uint32)",
			input: []byte{
				0x00, // Flags
				0x00, // SR Algorithm
				10, 0, 0, 1, // IPv4: 10.0.0.1
				0xFF, 0xFF, 0xFF, 0xFF, // SID: 4294967295
			},
			wantIPv4: []byte{10, 0, 0, 1},
			wantAlgo: 0x00,
			wantSID:  ptrUint32(4294967295),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := UnmarshalTypeCSegment(tt.input)
			if err != nil {
				t.Errorf("UnmarshalTypeCSegment() error = %v", err)
				return
			}

			typeCSeg, ok := seg.(TypeCSegment)
			if !ok {
				t.Error("Segment is not TypeCSegment")
				return
			}

			ipv4 := typeCSeg.GetIPv4Address()
			if len(ipv4) != 4 {
				t.Errorf("IPv4 address length = %d, want 4", len(ipv4))
				return
			}

			for i, b := range tt.wantIPv4 {
				if ipv4[i] != b {
					t.Errorf("IPv4 byte %d = %d, want %d", i, ipv4[i], b)
				}
			}

			if typeCSeg.GetSRAlgorithm() != tt.wantAlgo {
				t.Errorf("SR Algorithm = %d, want %d", typeCSeg.GetSRAlgorithm(), tt.wantAlgo)
			}

			sid, hasSID := typeCSeg.GetSID()
			if tt.wantSID == nil {
				if hasSID {
					t.Error("Expected no SID, but got one")
				}
			} else {
				if !hasSID {
					t.Error("Expected SID, but got none")
				} else if sid != *tt.wantSID {
					t.Errorf("SID = %d, want %d", sid, *tt.wantSID)
				}
			}

			if seg.GetType() != TypeC {
				t.Errorf("GetType() = %v, want TypeC", seg.GetType())
			}
		})
	}
}

func TestUnmarshalTypeCSegment_InvalidLength(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		length int
	}{
		{
			name:   "Too short - 5 bytes",
			input:  make([]byte, 5),
			length: 5,
		},
		{
			name:   "Too short - 3 bytes",
			input:  make([]byte, 3),
			length: 3,
		},
		{
			name:   "Invalid - 7 bytes",
			input:  make([]byte, 7),
			length: 7,
		},
		{
			name:   "Invalid - 9 bytes",
			input:  make([]byte, 9),
			length: 9,
		},
		{
			name:   "Too long - 11 bytes",
			input:  make([]byte, 11),
			length: 11,
		},
		{
			name:   "Empty",
			input:  []byte{},
			length: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalTypeCSegment(tt.input)
			if err == nil {
				t.Errorf("UnmarshalTypeCSegment() expected error for length %d, got nil", tt.length)
			}
		})
	}
}

func TestTypeCSegment_JSON(t *testing.T) {
	tests := []struct {
		name string
		seg  *typeCSegment
	}{
		{
			name: "Without SID",
			seg: &typeCSegment{
				flags:       NewSegmentFlags(0x00),
				srAlgorithm: 0x00,
				ipv4Address: []byte{192, 168, 1, 1},
				sid:         nil,
			},
		},
		{
			name: "With SID",
			seg: &typeCSegment{
				flags:       NewSegmentFlags(0x80),
				srAlgorithm: 0x01,
				ipv4Address: []byte{10, 0, 0, 1},
				sid:         ptrUint32(1000),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := json.Marshal(tt.seg)
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}

			// Unmarshal
			var result typeCSegment
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Verify IPv4
			if len(result.ipv4Address) != 4 {
				t.Errorf("Unmarshal() IPv4 length = %d, want 4", len(result.ipv4Address))
				return
			}

			for i, b := range tt.seg.ipv4Address {
				if result.ipv4Address[i] != b {
					t.Errorf("Unmarshal() IPv4 byte %d = %d, want %d", i, result.ipv4Address[i], b)
				}
			}

			// Verify SR Algorithm
			if result.srAlgorithm != tt.seg.srAlgorithm {
				t.Errorf("Unmarshal() SR Algorithm = %d, want %d", result.srAlgorithm, tt.seg.srAlgorithm)
			}

			// Verify flags
			if result.flags.Vflag != tt.seg.flags.Vflag {
				t.Errorf("Unmarshal() Vflag = %v, want %v", result.flags.Vflag, tt.seg.flags.Vflag)
			}
			if result.flags.Aflag != tt.seg.flags.Aflag {
				t.Errorf("Unmarshal() Aflag = %v, want %v", result.flags.Aflag, tt.seg.flags.Aflag)
			}
			if result.flags.Sflag != tt.seg.flags.Sflag {
				t.Errorf("Unmarshal() Sflag = %v, want %v", result.flags.Sflag, tt.seg.flags.Sflag)
			}
			if result.flags.Bflag != tt.seg.flags.Bflag {
				t.Errorf("Unmarshal() Bflag = %v, want %v", result.flags.Bflag, tt.seg.flags.Bflag)
			}

			// Verify SID
			if tt.seg.sid == nil {
				if result.sid != nil {
					t.Error("Unmarshal() expected no SID, but got one")
				}
			} else {
				if result.sid == nil {
					t.Error("Unmarshal() expected SID, but got none")
				} else if *result.sid != *tt.seg.sid {
					t.Errorf("Unmarshal() SID = %d, want %d", *result.sid, *tt.seg.sid)
				}
			}
		})
	}
}

func TestUnmarshalSegmentListSTLV_TypeC(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantIPv4 []byte
		wantAlgo byte
		wantSID  *uint32
	}{
		{
			name: "Type C without SID",
			input: []byte{
				0x03, // Type: Type C (3)
				0x06, // Length: 6 bytes
				0x00, // Flags
				0x00, // SR Algorithm
				192, 168, 1, 1, // IPv4
			},
			wantIPv4: []byte{192, 168, 1, 1},
			wantAlgo: 0x00,
			wantSID:  nil,
		},
		{
			name: "Type C with SID",
			input: []byte{
				0x03, // Type: Type C (3)
				0x0A, // Length: 10 bytes
				0x80, // Flags (V flag)
				0x01, // SR Algorithm
				10, 0, 0, 1, // IPv4
				0x00, 0x00, 0x03, 0xE8, // SID: 1000
			},
			wantIPv4: []byte{10, 0, 0, 1},
			wantAlgo: 0x01,
			wantSID:  ptrUint32(1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl, err := UnmarshalSegmentListSTLV(tt.input)
			if err != nil {
				t.Errorf("UnmarshalSegmentListSTLV() error = %v", err)
				return
			}

			if len(sl.Segment) != 1 {
				t.Errorf("Expected 1 segment, got %d", len(sl.Segment))
				return
			}

			typeCSeg, ok := sl.Segment[0].(TypeCSegment)
			if !ok {
				t.Error("Segment is not TypeCSegment")
				return
			}

			ipv4 := typeCSeg.GetIPv4Address()
			if len(ipv4) != 4 {
				t.Errorf("IPv4 address length = %d, want 4", len(ipv4))
			}

			for i, b := range tt.wantIPv4 {
				if ipv4[i] != b {
					t.Errorf("IPv4 byte %d = %d, want %d", i, ipv4[i], b)
				}
			}

			if typeCSeg.GetSRAlgorithm() != tt.wantAlgo {
				t.Errorf("SR Algorithm = %d, want %d", typeCSeg.GetSRAlgorithm(), tt.wantAlgo)
			}

			sid, hasSID := typeCSeg.GetSID()
			if tt.wantSID == nil {
				if hasSID {
					t.Error("Expected no SID, but got one")
				}
			} else {
				if !hasSID {
					t.Error("Expected SID, but got none")
				} else if sid != *tt.wantSID {
					t.Errorf("SID = %d, want %d", sid, *tt.wantSID)
				}
			}
		})
	}
}

// Helper function to create pointer to uint32
func ptrUint32(v uint32) *uint32 {
	return &v
}

// ============================================================================
// Type D Segment Tests (IPv6 + SR Algorithm + optional SID)
// ============================================================================

func TestUnmarshalTypeDSegment_Valid(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantIPv6    []byte
		wantAlgo    byte
		wantSID     *uint32
	}{
		{
			name: "Without SID (18 bytes)",
			input: []byte{
				0x00, // Flags
				0x00, // SR Algorithm
				// IPv6: 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantIPv6: []byte{
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantAlgo: 0x00,
			wantSID:  nil,
		},
		{
			name: "With SID (22 bytes)",
			input: []byte{
				0x80, // Flags (V flag set)
				0x01, // SR Algorithm
				// IPv6: fe80::1
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x07, 0xD0, // SID: 2000
			},
			wantIPv6: []byte{
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantAlgo: 0x01,
			wantSID:  ptrUint32(2000),
		},
		{
			name: "All zeros without SID",
			input: []byte{
				0x00, 0x00, // Flags, SR Algorithm
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IPv6
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			wantIPv6: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			wantAlgo: 0x00,
			wantSID:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := UnmarshalTypeDSegment(tt.input)
			if err != nil {
				t.Errorf("UnmarshalTypeDSegment() error = %v", err)
				return
			}

			typeDSeg, ok := seg.(TypeDSegment)
			if !ok {
				t.Error("Segment is not TypeDSegment")
				return
			}

			ipv6 := typeDSeg.GetIPv6Address()
			if len(ipv6) != 16 {
				t.Errorf("IPv6 address length = %d, want 16", len(ipv6))
				return
			}

			for i, b := range tt.wantIPv6 {
				if ipv6[i] != b {
					t.Errorf("IPv6 byte %d = %02x, want %02x", i, ipv6[i], b)
				}
			}

			if typeDSeg.GetSRAlgorithm() != tt.wantAlgo {
				t.Errorf("SR Algorithm = %d, want %d", typeDSeg.GetSRAlgorithm(), tt.wantAlgo)
			}

			sid, hasSID := typeDSeg.GetSID()
			if tt.wantSID == nil {
				if hasSID {
					t.Error("Expected no SID, but got one")
				}
			} else {
				if !hasSID {
					t.Error("Expected SID, but got none")
				} else if sid != *tt.wantSID {
					t.Errorf("SID = %d, want %d", sid, *tt.wantSID)
				}
			}

			if seg.GetType() != TypeD {
				t.Errorf("GetType() = %v, want TypeD", seg.GetType())
			}
		})
	}
}

func TestUnmarshalTypeDSegment_InvalidLength(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		length int
	}{
		{
			name:   "Too short - 17 bytes",
			input:  make([]byte, 17),
			length: 17,
		},
		{
			name:   "Too short - 10 bytes",
			input:  make([]byte, 10),
			length: 10,
		},
		{
			name:   "Invalid - 19 bytes",
			input:  make([]byte, 19),
			length: 19,
		},
		{
			name:   "Invalid - 21 bytes",
			input:  make([]byte, 21),
			length: 21,
		},
		{
			name:   "Too long - 23 bytes",
			input:  make([]byte, 23),
			length: 23,
		},
		{
			name:   "Empty",
			input:  []byte{},
			length: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalTypeDSegment(tt.input)
			if err == nil {
				t.Errorf("UnmarshalTypeDSegment() expected error for length %d, got nil", tt.length)
			}
		})
	}
}

func TestTypeDSegment_JSON(t *testing.T) {
	tests := []struct {
		name string
		seg  *typeDSegment
	}{
		{
			name: "Without SID",
			seg: &typeDSegment{
				flags:       NewSegmentFlags(0x00),
				srAlgorithm: 0x00,
				ipv6Address: []byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				sid: nil,
			},
		},
		{
			name: "With SID",
			seg: &typeDSegment{
				flags:       NewSegmentFlags(0x80),
				srAlgorithm: 0x01,
				ipv6Address: []byte{
					0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
				sid: ptrUint32(2000),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := json.Marshal(tt.seg)
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}

			// Unmarshal
			var result typeDSegment
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Verify IPv6
			if len(result.ipv6Address) != 16 {
				t.Errorf("Unmarshal() IPv6 length = %d, want 16", len(result.ipv6Address))
				return
			}

			for i, b := range tt.seg.ipv6Address {
				if result.ipv6Address[i] != b {
					t.Errorf("Unmarshal() IPv6 byte %d = %02x, want %02x", i, result.ipv6Address[i], b)
				}
			}

			// Verify SR Algorithm
			if result.srAlgorithm != tt.seg.srAlgorithm {
				t.Errorf("Unmarshal() SR Algorithm = %d, want %d", result.srAlgorithm, tt.seg.srAlgorithm)
			}

			// Verify flags
			if result.flags.Vflag != tt.seg.flags.Vflag {
				t.Errorf("Unmarshal() Vflag = %v, want %v", result.flags.Vflag, tt.seg.flags.Vflag)
			}
			if result.flags.Aflag != tt.seg.flags.Aflag {
				t.Errorf("Unmarshal() Aflag = %v, want %v", result.flags.Aflag, tt.seg.flags.Aflag)
			}
			if result.flags.Sflag != tt.seg.flags.Sflag {
				t.Errorf("Unmarshal() Sflag = %v, want %v", result.flags.Sflag, tt.seg.flags.Sflag)
			}
			if result.flags.Bflag != tt.seg.flags.Bflag {
				t.Errorf("Unmarshal() Bflag = %v, want %v", result.flags.Bflag, tt.seg.flags.Bflag)
			}

			// Verify SID
			if tt.seg.sid == nil {
				if result.sid != nil {
					t.Error("Unmarshal() expected no SID, but got one")
				}
			} else {
				if result.sid == nil {
					t.Error("Unmarshal() expected SID, but got none")
				} else if *result.sid != *tt.seg.sid {
					t.Errorf("Unmarshal() SID = %d, want %d", *result.sid, *tt.seg.sid)
				}
			}
		})
	}
}

func TestUnmarshalSegmentListSTLV_TypeD(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantIPv6 []byte
		wantAlgo byte
		wantSID  *uint32
	}{
		{
			name: "Type D without SID",
			input: []byte{
				0x04, // Type: Type D (4)
				0x12, // Length: 18 bytes
				0x00, // Flags
				0x00, // SR Algorithm
				// IPv6: 2001:db8::1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantIPv6: []byte{
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantAlgo: 0x00,
			wantSID:  nil,
		},
		{
			name: "Type D with SID",
			input: []byte{
				0x04, // Type: Type D (4)
				0x16, // Length: 22 bytes
				0x80, // Flags (V flag)
				0x01, // SR Algorithm
				// IPv6: fe80::1
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x07, 0xD0, // SID: 2000
			},
			wantIPv6: []byte{
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantAlgo: 0x01,
			wantSID:  ptrUint32(2000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl, err := UnmarshalSegmentListSTLV(tt.input)
			if err != nil {
				t.Errorf("UnmarshalSegmentListSTLV() error = %v", err)
				return
			}

			if len(sl.Segment) != 1 {
				t.Errorf("Expected 1 segment, got %d", len(sl.Segment))
				return
			}

			typeDSeg, ok := sl.Segment[0].(TypeDSegment)
			if !ok {
				t.Error("Segment is not TypeDSegment")
				return
			}

			ipv6 := typeDSeg.GetIPv6Address()
			if len(ipv6) != 16 {
				t.Errorf("IPv6 address length = %d, want 16", len(ipv6))
			}

			for i, b := range tt.wantIPv6 {
				if ipv6[i] != b {
					t.Errorf("IPv6 byte %d = %02x, want %02x", i, ipv6[i], b)
				}
			}

			if typeDSeg.GetSRAlgorithm() != tt.wantAlgo {
				t.Errorf("SR Algorithm = %d, want %d", typeDSeg.GetSRAlgorithm(), tt.wantAlgo)
			}

			sid, hasSID := typeDSeg.GetSID()
			if tt.wantSID == nil {
				if hasSID {
					t.Error("Expected no SID, but got one")
				}
			} else {
				if !hasSID {
					t.Error("Expected SID, but got none")
				} else if sid != *tt.wantSID {
					t.Errorf("SID = %d, want %d", sid, *tt.wantSID)
				}
			}
		})
	}
}

// TestTypeESegment_JSON tests Type E JSON marshaling/unmarshaling
func TestTypeESegment_JSON(t *testing.T) {
	tests := []struct {
		name    string
		segment *typeESegment
	}{
		{
			name: "Type E with SID",
			segment: &typeESegment{
				flags:            NewSegmentFlags(0x80),
				localInterfaceID: 10,
				ipv4Address:      []byte{10, 0, 0, 1},
				sid:              ptrUint32(1000),
			},
		},
		{
			name: "Type E without SID",
			segment: &typeESegment{
				flags:            NewSegmentFlags(0x00),
				localInterfaceID: 1,
				ipv4Address:      []byte{192, 168, 1, 1},
				sid:              nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.segment)
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}

			var decoded typeESegment
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Verify all flags preserved
			if decoded.flags.Vflag != tt.segment.flags.Vflag {
				t.Errorf("Unmarshal() Vflag = %v, want %v", decoded.flags.Vflag, tt.segment.flags.Vflag)
			}
			if decoded.flags.Aflag != tt.segment.flags.Aflag {
				t.Errorf("Unmarshal() Aflag = %v, want %v", decoded.flags.Aflag, tt.segment.flags.Aflag)
			}
			if decoded.flags.Sflag != tt.segment.flags.Sflag {
				t.Errorf("Unmarshal() Sflag = %v, want %v", decoded.flags.Sflag, tt.segment.flags.Sflag)
			}
			if decoded.flags.Bflag != tt.segment.flags.Bflag {
				t.Errorf("Unmarshal() Bflag = %v, want %v", decoded.flags.Bflag, tt.segment.flags.Bflag)
			}

			// Verify IPv4 address
			if len(decoded.ipv4Address) != len(tt.segment.ipv4Address) {
				t.Errorf("IPv4 address length = %d, want %d", len(decoded.ipv4Address), len(tt.segment.ipv4Address))
			}
			for i := range tt.segment.ipv4Address {
				if decoded.ipv4Address[i] != tt.segment.ipv4Address[i] {
					t.Errorf("IPv4 byte %d = %d, want %d", i, decoded.ipv4Address[i], tt.segment.ipv4Address[i])
				}
			}

			// Verify interface ID
			if decoded.localInterfaceID != tt.segment.localInterfaceID {
				t.Errorf("LocalInterfaceID = %d, want %d", decoded.localInterfaceID, tt.segment.localInterfaceID)
			}

			// Verify SID
			if tt.segment.sid == nil {
				if decoded.sid != nil {
					t.Errorf("Expected no SID, but got %v", *decoded.sid)
				}
			} else {
				if decoded.sid == nil {
					t.Error("Expected SID, but got nil")
				} else if *decoded.sid != *tt.segment.sid {
					t.Errorf("SID = %d, want %d", *decoded.sid, *tt.segment.sid)
				}
			}

			// Verify round-trip
			if decoded.GetType() != TypeE {
				t.Errorf("Type = %v, want %v", decoded.GetType(), TypeE)
			}
		})
	}
}

// TestUnmarshalSegmentListSTLV_TypeE tests Type E in SegmentList context
func TestUnmarshalSegmentListSTLV_TypeE(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantIPv4    []byte
		wantIfaceID uint32
		wantSID     *uint32
	}{
		{
			name: "Type E without SID",
			input: []byte{
				0x05, // Type: Type E (5)
				0x0A, // Length: 10 bytes
				0x00, // Flags
				0x00, // Reserved
				0x00, 0x00, 0x00, 0x01, // Interface ID: 1
				192, 168, 1, 1, // IPv4: 192.168.1.1
			},
			wantIPv4:    []byte{192, 168, 1, 1},
			wantIfaceID: 1,
			wantSID:     nil,
		},
		{
			name: "Type E with SID",
			input: []byte{
				0x05, // Type: Type E (5)
				0x0E, // Length: 14 bytes
				0x80, // Flags (V flag)
				0x00, // Reserved
				0x00, 0x00, 0x00, 0x0A, // Interface ID: 10
				10, 0, 0, 1, // IPv4: 10.0.0.1
				0x00, 0x00, 0x03, 0xE8, // SID: 1000
			},
			wantIPv4:    []byte{10, 0, 0, 1},
			wantIfaceID: 10,
			wantSID:     ptrUint32(1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl, err := UnmarshalSegmentListSTLV(tt.input)
			if err != nil {
				t.Errorf("UnmarshalSegmentListSTLV() error = %v", err)
				return
			}

			if len(sl.Segment) != 1 {
				t.Errorf("Expected 1 segment, got %d", len(sl.Segment))
				return
			}

			typeESeg, ok := sl.Segment[0].(TypeESegment)
			if !ok {
				t.Error("Segment is not TypeESegment")
				return
			}

			ipv4 := typeESeg.GetIPv4Address()
			if len(ipv4) != 4 {
				t.Errorf("IPv4 address length = %d, want 4", len(ipv4))
			}

			for i, b := range tt.wantIPv4 {
				if ipv4[i] != b {
					t.Errorf("IPv4 byte %d = %d, want %d", i, ipv4[i], b)
				}
			}

			if typeESeg.GetLocalInterfaceID() != tt.wantIfaceID {
				t.Errorf("Interface ID = %d, want %d", typeESeg.GetLocalInterfaceID(), tt.wantIfaceID)
			}

			sid, hasSID := typeESeg.GetSID()
			if tt.wantSID == nil {
				if hasSID {
					t.Error("Expected no SID, but got one")
				}
			} else {
				if !hasSID {
					t.Error("Expected SID, but got none")
				} else if sid != *tt.wantSID {
					t.Errorf("SID = %d, want %d", sid, *tt.wantSID)
				}
			}
		})
	}
}

// ============================================================================
// Type E Segment Tests (Direct Unmarshal)
// ============================================================================

func TestUnmarshalTypeESegment_Valid(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantSID   bool
	}{
		{
			name:    "IPv4 and InterfaceID only (10 bytes)",
			// Flags + Reserved + 4 bytes Interface ID + 4 bytes IPv4
			input:   []byte{0, 0, 0, 0, 0, 1, 192, 0, 2, 1},
			wantSID: false,
		},
		{
			name:    "IPv4, InterfaceID and SID (14 bytes)",
			// Flags + Reserved + 4 bytes Interface ID + 4 bytes IPv4 + 4 bytes SID
			input:   []byte{0, 0, 0, 0, 0, 2, 192, 0, 2, 2, 0, 0, 0, 42},
			wantSID: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := UnmarshalTypeESegment(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalTypeESegment() error = %v", err)
			}

			typeESeg, ok := seg.(TypeESegment)
			if !ok {
				t.Fatal("Segment is not TypeESegment")
			}

			ipv4 := typeESeg.GetIPv4Address()
			if len(ipv4) != 4 {
				t.Errorf("IPv4 address length = %d, want 4", len(ipv4))
			}

			_, hasSID := typeESeg.GetSID()
			if hasSID != tt.wantSID {
				t.Errorf("GetSID presence = %v, want %v", hasSID, tt.wantSID)
			}
		})
	}
}

func TestUnmarshalTypeESegment_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty",
			input: []byte{},
		},
		{
			name:  "1 byte",
			input: []byte{0x00},
		},
		{
			name:  "2 bytes",
			input: []byte{0x00, 0x01},
		},
		{
			name:  "3 bytes",
			input: []byte{0x00, 0x01, 0x02},
		},
		{
			name:  "4 bytes",
			input: []byte{0x00, 0x01, 0x02, 0x03},
		},
		{
			name:  "5 bytes",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:  "6 bytes",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			name:  "7 bytes",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		},
		{
			name:  "8 bytes",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		},
		{
			name:  "9 bytes",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
		{
			name:  "11 bytes",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		},
		{
			name:  "12 bytes",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		},
		{
			name:  "13 bytes",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
		},
		{
			name:  "15 bytes",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := UnmarshalTypeESegment(tt.input); err == nil {
				t.Errorf("UnmarshalTypeESegment() with %s input length %d, expected error but got none", tt.name, len(tt.input))
			}
		})
	}
}

// ============================================================================
// Type F Segment Tests (Direct Unmarshal)
// ============================================================================

func TestUnmarshalTypeFSegment_Valid(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		wantLocalIPv4  []byte
		wantRemoteIPv4 []byte
		wantSID        *uint32
	}{
		{
			name: "without SID (10 bytes)",
			input: []byte{
				0x00, 0x00, // Flags + Reserved
				192, 168, 1, 1, // Local IPv4
				10, 0, 0, 1, // Remote IPv4
			},
			wantLocalIPv4:  []byte{192, 168, 1, 1},
			wantRemoteIPv4: []byte{10, 0, 0, 1},
			wantSID:        nil,
		},
		{
			name: "with SID (14 bytes)",
			input: []byte{
				0x80, 0x00, // Flags (V flag set) + Reserved
				10, 0, 0, 1,   // Local IPv4
				172, 16, 0, 1, // Remote IPv4
				0x00, 0x00, 0x03, 0xE8, // SID: 1000
			},
			wantLocalIPv4:  []byte{10, 0, 0, 1},
			wantRemoteIPv4: []byte{172, 16, 0, 1},
			wantSID:        ptrUint32(1000),
		},
		{
			name: "all zeros without SID",
			input: []byte{
				0x00, 0x00,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			wantLocalIPv4:  []byte{0, 0, 0, 0},
			wantRemoteIPv4: []byte{0, 0, 0, 0},
			wantSID:        nil,
		},
		{
			name: "SID value zero (14 bytes)",
			input: []byte{
				0x80, 0x00,
				1, 1, 1, 1,
				2, 2, 2, 2,
				0x00, 0x00, 0x00, 0x00,
			},
			wantLocalIPv4:  []byte{1, 1, 1, 1},
			wantRemoteIPv4: []byte{2, 2, 2, 2},
			wantSID:        ptrUint32(0),
		},
		{
			name: "max SID value (14 bytes)",
			input: []byte{
				0x80, 0x00,
				255, 255, 255, 255,
				10, 0, 0, 1,
				0xFF, 0xFF, 0xFF, 0xFF,
			},
			wantLocalIPv4:  []byte{255, 255, 255, 255},
			wantRemoteIPv4: []byte{10, 0, 0, 1},
			wantSID:        ptrUint32(0xFFFFFFFF),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := UnmarshalTypeFSegment(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalTypeFSegment() error = %v", err)
			}
			if seg.GetType() != TypeF {
				t.Errorf("GetType() = %v, want %v", seg.GetType(), TypeF)
			}

			typeFSeg, ok := seg.(TypeFSegment)
			if !ok {
				t.Fatal("Segment does not implement TypeFSegment interface")
			}

			localIPv4 := typeFSeg.GetLocalIPv4Address()
			if len(localIPv4) != 4 {
				t.Fatalf("Local IPv4 length = %d, want 4", len(localIPv4))
			}
			for i, b := range tt.wantLocalIPv4 {
				if localIPv4[i] != b {
					t.Errorf("Local IPv4[%d] = %d, want %d", i, localIPv4[i], b)
				}
			}

			remoteIPv4 := typeFSeg.GetRemoteIPv4Address()
			if len(remoteIPv4) != 4 {
				t.Fatalf("Remote IPv4 length = %d, want 4", len(remoteIPv4))
			}
			for i, b := range tt.wantRemoteIPv4 {
				if remoteIPv4[i] != b {
					t.Errorf("Remote IPv4[%d] = %d, want %d", i, remoteIPv4[i], b)
				}
			}

			sid, hasSID := typeFSeg.GetSID()
			if tt.wantSID == nil {
				if hasSID {
					t.Errorf("GetSID() hasSID = true, want false")
				}
			} else {
				if !hasSID {
					t.Errorf("GetSID() hasSID = false, want true")
				}
				if sid != *tt.wantSID {
					t.Errorf("GetSID() sid = %d, want %d", sid, *tt.wantSID)
				}
			}
		})
	}
}

func TestUnmarshalTypeFSegment_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "empty", input: []byte{}},
		{name: "1 byte", input: []byte{0x00}},
		{name: "2 bytes", input: []byte{0x00, 0x01}},
		{name: "9 bytes", input: make([]byte, 9)},
		{name: "11 bytes", input: make([]byte, 11)},
		{name: "12 bytes", input: make([]byte, 12)},
		{name: "13 bytes", input: make([]byte, 13)},
		{name: "15 bytes", input: make([]byte, 15)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := UnmarshalTypeFSegment(tt.input); err == nil {
				t.Errorf("UnmarshalTypeFSegment() with length %d expected error, got nil", len(tt.input))
			}
		})
	}
}

func TestTypeFSegment_JSON(t *testing.T) {
	tests := []struct {
		name string
		seg  *typeFSegment
	}{
		{
			name: "without SID",
			seg: &typeFSegment{
				flags:             NewSegmentFlags(0x00),
				localIPv4Address:  []byte{192, 168, 1, 1},
				remoteIPv4Address: []byte{10, 0, 0, 1},
				sid:               nil,
			},
		},
		{
			name: "with SID and V flag",
			seg: &typeFSegment{
				flags:             NewSegmentFlags(0x80),
				localIPv4Address:  []byte{10, 0, 0, 1},
				remoteIPv4Address: []byte{172, 16, 0, 1},
				sid:               ptrUint32(2000),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := json.Marshal(tt.seg)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			var result typeFSegment
			if err := json.Unmarshal(jsonBytes, &result); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}

			if result.flags.Vflag != tt.seg.flags.Vflag {
				t.Errorf("Vflag = %v, want %v", result.flags.Vflag, tt.seg.flags.Vflag)
			}
			if result.flags.Aflag != tt.seg.flags.Aflag {
				t.Errorf("Aflag = %v, want %v", result.flags.Aflag, tt.seg.flags.Aflag)
			}
			if result.flags.Sflag != tt.seg.flags.Sflag {
				t.Errorf("Sflag = %v, want %v", result.flags.Sflag, tt.seg.flags.Sflag)
			}
			if result.flags.Bflag != tt.seg.flags.Bflag {
				t.Errorf("Bflag = %v, want %v", result.flags.Bflag, tt.seg.flags.Bflag)
			}

			jsonBytes2, err := json.Marshal(&result)
			if err != nil {
				t.Fatalf("Marshal() after Unmarshal() error = %v", err)
			}
			if string(jsonBytes) != string(jsonBytes2) {
				t.Errorf("JSON round-trip failed.\nOriginal: %s\nAfter:    %s", jsonBytes, jsonBytes2)
			}
		})
	}
}

func TestUnmarshalSegmentListSTLV_TypeF(t *testing.T) {
	tests := []struct {
		name             string
		input            []byte
		wantSegmentCount int
	}{
		{
			name: "single without SID",
			input: []byte{
				0x06, 0x0A, // Type F, length 10
				0x00, 0x00, // Flags + Reserved
				192, 168, 1, 1, // Local IPv4
				10, 0, 0, 1, // Remote IPv4
			},
			wantSegmentCount: 1,
		},
		{
			name: "single with SID",
			input: []byte{
				0x06, 0x0E, // Type F, length 14
				0x80, 0x00, // Flags (V flag) + Reserved
				10, 0, 0, 1,   // Local IPv4
				172, 16, 0, 1, // Remote IPv4
				0x00, 0x00, 0x07, 0xD0, // SID: 2000
			},
			wantSegmentCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl, err := UnmarshalSegmentListSTLV(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalSegmentListSTLV() error = %v", err)
			}
			if len(sl.Segment) != tt.wantSegmentCount {
				t.Errorf("Segment count = %d, want %d", len(sl.Segment), tt.wantSegmentCount)
			}
			if len(sl.Segment) > 0 && sl.Segment[0].GetType() != TypeF {
				t.Errorf("Segment[0] type = %v, want %v", sl.Segment[0].GetType(), TypeF)
			}
		})
	}
}

// TestSegmentList_JSON_TypeF tests SegmentList JSON marshal/unmarshal with a Type F segment.
// This ensures SegmentList.UnmarshalJSON properly dispatches to typeFSegment.unmarshalJSONObj.
func TestSegmentList_JSON_TypeF(t *testing.T) {
	localIPv4 := []byte{10, 0, 0, 1}
	remoteIPv4 := []byte{172, 16, 0, 1}
	sidVal := uint32(2000)

	sl := &SegmentList{
		Weight: &Weight{Flags: 0, Weight: 100},
		Segment: []Segment{
			&typeFSegment{
				flags:             NewSegmentFlags(0x80), // V-flag set
				localIPv4Address:  localIPv4,
				remoteIPv4Address: remoteIPv4,
				sid:               &sidVal,
			},
		},
	}

	data, err := json.Marshal(sl)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var result SegmentList
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if result.Weight == nil {
		t.Fatal("Unmarshal() Weight is nil")
	}
	if result.Weight.Weight != 100 {
		t.Errorf("Unmarshal() Weight = %d, want 100", result.Weight.Weight)
	}

	if len(result.Segment) != 1 {
		t.Fatalf("Unmarshal() segment count = %d, want 1", len(result.Segment))
	}

	seg := result.Segment[0]
	if seg.GetType() != TypeF {
		t.Errorf("Unmarshal() segment type = %v, want TypeF", seg.GetType())
	}

	typeFSeg, ok := seg.(TypeFSegment)
	if !ok {
		t.Fatal("Unmarshal() segment does not implement TypeFSegment")
	}

	gotLocal := typeFSeg.GetLocalIPv4Address()
	if len(gotLocal) != 4 {
		t.Fatalf("GetLocalIPv4Address() length = %d, want 4", len(gotLocal))
	}
	for i, b := range localIPv4 {
		if gotLocal[i] != b {
			t.Errorf("LocalIPv4[%d] = %d, want %d", i, gotLocal[i], b)
		}
	}

	gotRemote := typeFSeg.GetRemoteIPv4Address()
	if len(gotRemote) != 4 {
		t.Fatalf("GetRemoteIPv4Address() length = %d, want 4", len(gotRemote))
	}
	for i, b := range remoteIPv4 {
		if gotRemote[i] != b {
			t.Errorf("RemoteIPv4[%d] = %d, want %d", i, gotRemote[i], b)
		}
	}

	gotSID, hasSID := typeFSeg.GetSID()
	if !hasSID {
		t.Fatal("GetSID() hasSID = false, want true")
	}
	if gotSID != sidVal {
		t.Errorf("GetSID() = %d, want %d", gotSID, sidVal)
	}

	flags := seg.GetFlags()
	if flags == nil {
		t.Fatal("Unmarshal() flags is nil")
	}
	if !flags.Vflag {
		t.Error("Unmarshal() V-flag not preserved")
	}
}
func TestUnmarshalTypeGSegment_Valid(t *testing.T) {
	localIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	remoteIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	tests := []struct {
		name              string
		input             []byte
		wantLocalIfaceID  uint32
		wantLocalIPv6     []byte
		wantRemoteIfaceID uint32
		wantRemoteIPv6    []byte
		wantSID           *uint32
	}{
		{
			name: "without SID (42 bytes)",
			input: append(append([]byte{
				0x00, 0x00, // Flags + Reserved
				0x00, 0x00, 0x00, 0x01, // Local Interface ID: 1
			}, localIPv6...), append([]byte{
				0x00, 0x00, 0x00, 0x02, // Remote Interface ID: 2
			}, remoteIPv6...)...),
			wantLocalIfaceID:  1,
			wantLocalIPv6:     localIPv6,
			wantRemoteIfaceID: 2,
			wantRemoteIPv6:    remoteIPv6,
			wantSID:           nil,
		},
		{
			name: "with SID (46 bytes)",
			input: append(append([]byte{
				0x80, 0x00, // Flags (V flag) + Reserved
				0x00, 0x00, 0x00, 0x03, // Local Interface ID: 3
			}, localIPv6...), append([]byte{
				0x00, 0x00, 0x00, 0x04, // Remote Interface ID: 4
			}, append(remoteIPv6, 0x00, 0x00, 0x03, 0xE8)...)...),
			wantLocalIfaceID:  3,
			wantLocalIPv6:     localIPv6,
			wantRemoteIfaceID: 4,
			wantRemoteIPv6:    remoteIPv6,
			wantSID:           ptrUint32(1000),
		},
		{
			name: "SID value zero (46 bytes)",
			input: append(append([]byte{
				0x80, 0x00,
				0x00, 0x00, 0x00, 0x01,
			}, localIPv6...), append([]byte{
				0x00, 0x00, 0x00, 0x02,
			}, append(remoteIPv6, 0x00, 0x00, 0x00, 0x00)...)...),
			wantLocalIfaceID:  1,
			wantLocalIPv6:     localIPv6,
			wantRemoteIfaceID: 2,
			wantRemoteIPv6:    remoteIPv6,
			wantSID:           ptrUint32(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := UnmarshalTypeGSegment(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalTypeGSegment() error = %v", err)
			}
			if seg.GetType() != TypeG {
				t.Errorf("GetType() = %v, want %v", seg.GetType(), TypeG)
			}

			typeGSeg, ok := seg.(TypeGSegment)
			if !ok {
				t.Fatal("Segment does not implement TypeGSegment interface")
			}

			if typeGSeg.GetLocalInterfaceID() != tt.wantLocalIfaceID {
				t.Errorf("GetLocalInterfaceID() = %d, want %d", typeGSeg.GetLocalInterfaceID(), tt.wantLocalIfaceID)
			}

			localIPv6 := typeGSeg.GetLocalIPv6Address()
			if len(localIPv6) != 16 {
				t.Errorf("Local IPv6 length = %d, want 16", len(localIPv6))
			}
			for i, b := range tt.wantLocalIPv6 {
				if localIPv6[i] != b {
					t.Errorf("Local IPv6[%d] = %d, want %d", i, localIPv6[i], b)
				}
			}

			if typeGSeg.GetRemoteInterfaceID() != tt.wantRemoteIfaceID {
				t.Errorf("GetRemoteInterfaceID() = %d, want %d", typeGSeg.GetRemoteInterfaceID(), tt.wantRemoteIfaceID)
			}

			remoteIPv6 := typeGSeg.GetRemoteIPv6Address()
			if len(remoteIPv6) != 16 {
				t.Errorf("Remote IPv6 length = %d, want 16", len(remoteIPv6))
			}
			for i, b := range tt.wantRemoteIPv6 {
				if remoteIPv6[i] != b {
					t.Errorf("Remote IPv6[%d] = %d, want %d", i, remoteIPv6[i], b)
				}
			}

			sid, hasSID := typeGSeg.GetSID()
			if tt.wantSID == nil {
				if hasSID {
					t.Errorf("GetSID() hasSID = true, want false")
				}
			} else {
				if !hasSID {
					t.Errorf("GetSID() hasSID = false, want true")
				}
				if sid != *tt.wantSID {
					t.Errorf("GetSID() sid = %d, want %d", sid, *tt.wantSID)
				}
			}
		})
	}
}

func TestUnmarshalTypeGSegment_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "empty", input: []byte{}},
		{name: "1 byte", input: make([]byte, 1)},
		{name: "41 bytes", input: make([]byte, 41)},
		{name: "43 bytes", input: make([]byte, 43)},
		{name: "44 bytes", input: make([]byte, 44)},
		{name: "45 bytes", input: make([]byte, 45)},
		{name: "47 bytes", input: make([]byte, 47)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := UnmarshalTypeGSegment(tt.input); err == nil {
				t.Errorf("UnmarshalTypeGSegment() with length %d expected error, got nil", len(tt.input))
			}
		})
	}
}

func TestTypeGSegment_JSON(t *testing.T) {
	localIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	remoteIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	tests := []struct {
		name string
		seg  *typeGSegment
	}{
		{
			name: "without SID",
			seg: &typeGSegment{
				flags:             NewSegmentFlags(0x00),
				localInterfaceID:  1,
				localIPv6Address:  localIPv6,
				remoteInterfaceID: 2,
				remoteIPv6Address: remoteIPv6,
				sid:               nil,
			},
		},
		{
			name: "with SID and V flag",
			seg: &typeGSegment{
				flags:             NewSegmentFlags(0x80),
				localInterfaceID:  3,
				localIPv6Address:  localIPv6,
				remoteInterfaceID: 4,
				remoteIPv6Address: remoteIPv6,
				sid:               ptrUint32(5000),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := json.Marshal(tt.seg)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			var result typeGSegment
			if err := json.Unmarshal(jsonBytes, &result); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}

			if result.flags.Vflag != tt.seg.flags.Vflag {
				t.Errorf("Vflag = %v, want %v", result.flags.Vflag, tt.seg.flags.Vflag)
			}
			if result.flags.Aflag != tt.seg.flags.Aflag {
				t.Errorf("Aflag = %v, want %v", result.flags.Aflag, tt.seg.flags.Aflag)
			}
			if result.flags.Sflag != tt.seg.flags.Sflag {
				t.Errorf("Sflag = %v, want %v", result.flags.Sflag, tt.seg.flags.Sflag)
			}
			if result.flags.Bflag != tt.seg.flags.Bflag {
				t.Errorf("Bflag = %v, want %v", result.flags.Bflag, tt.seg.flags.Bflag)
			}

			if result.localInterfaceID != tt.seg.localInterfaceID {
				t.Errorf("localInterfaceID = %d, want %d", result.localInterfaceID, tt.seg.localInterfaceID)
			}
			if len(result.localIPv6Address) != len(tt.seg.localIPv6Address) {
				t.Fatalf("localIPv6Address length = %d, want %d", len(result.localIPv6Address), len(tt.seg.localIPv6Address))
			}
			for i := range tt.seg.localIPv6Address {
				if result.localIPv6Address[i] != tt.seg.localIPv6Address[i] {
					t.Errorf("localIPv6Address[%d] = %d, want %d", i, result.localIPv6Address[i], tt.seg.localIPv6Address[i])
				}
			}
			if result.remoteInterfaceID != tt.seg.remoteInterfaceID {
				t.Errorf("remoteInterfaceID = %d, want %d", result.remoteInterfaceID, tt.seg.remoteInterfaceID)
			}
			if len(result.remoteIPv6Address) != len(tt.seg.remoteIPv6Address) {
				t.Fatalf("remoteIPv6Address length = %d, want %d", len(result.remoteIPv6Address), len(tt.seg.remoteIPv6Address))
			}
			for i := range tt.seg.remoteIPv6Address {
				if result.remoteIPv6Address[i] != tt.seg.remoteIPv6Address[i] {
					t.Errorf("remoteIPv6Address[%d] = %d, want %d", i, result.remoteIPv6Address[i], tt.seg.remoteIPv6Address[i])
				}
			}
			if tt.seg.sid == nil {
				if result.sid != nil {
					t.Errorf("sid = %d, want nil", *result.sid)
				}
			} else {
				if result.sid == nil {
					t.Error("sid = nil, want non-nil")
				} else if *result.sid != *tt.seg.sid {
					t.Errorf("sid = %d, want %d", *result.sid, *tt.seg.sid)
				}
			}

			jsonBytes2, err := json.Marshal(&result)
			if err != nil {
				t.Fatalf("Marshal() after Unmarshal() error = %v", err)
			}
			if string(jsonBytes) != string(jsonBytes2) {
				t.Errorf("JSON round-trip failed.\nOriginal: %s\nAfter:    %s", jsonBytes, jsonBytes2)
			}
		})
	}
}

func TestUnmarshalSegmentListSTLV_TypeG(t *testing.T) {
	localIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	remoteIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	tests := []struct {
		name              string
		input             []byte
		wantLocalIfaceID  uint32
		wantLocalIPv6     []byte
		wantRemoteIfaceID uint32
		wantRemoteIPv6    []byte
		wantSID           *uint32
	}{
		{
			name: "single without SID",
			input: append([]byte{
				0x07, 0x2A, // Type G, length 42
				0x00, 0x00, // Flags + Reserved
				0x00, 0x00, 0x00, 0x01, // Local Interface ID
			}, append(localIPv6, append([]byte{0x00, 0x00, 0x00, 0x02}, remoteIPv6...)...)...),
			wantLocalIfaceID:  1,
			wantLocalIPv6:     localIPv6,
			wantRemoteIfaceID: 2,
			wantRemoteIPv6:    remoteIPv6,
			wantSID:           nil,
		},
		{
			name: "single with SID",
			input: append([]byte{
				0x07, 0x2E, // Type G, length 46
				0x80, 0x00, // Flags (V flag) + Reserved
				0x00, 0x00, 0x00, 0x01,
			}, append(localIPv6, append([]byte{0x00, 0x00, 0x00, 0x02}, append(remoteIPv6, 0x00, 0x00, 0x07, 0xD0)...)...)...),
			wantLocalIfaceID:  1,
			wantLocalIPv6:     localIPv6,
			wantRemoteIfaceID: 2,
			wantRemoteIPv6:    remoteIPv6,
			wantSID:           ptrUint32(2000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl, err := UnmarshalSegmentListSTLV(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalSegmentListSTLV() error = %v", err)
			}
			if len(sl.Segment) != 1 {
				t.Fatalf("Segment count = %d, want 1", len(sl.Segment))
			}

			typeGSeg, ok := sl.Segment[0].(TypeGSegment)
			if !ok {
				t.Fatal("Segment is not TypeGSegment")
			}

			if typeGSeg.GetLocalInterfaceID() != tt.wantLocalIfaceID {
				t.Errorf("LocalInterfaceID = %d, want %d", typeGSeg.GetLocalInterfaceID(), tt.wantLocalIfaceID)
			}
			localIPv6Got := typeGSeg.GetLocalIPv6Address()
			if len(localIPv6Got) != len(tt.wantLocalIPv6) {
				t.Fatalf("localIPv6Address length = %d, want %d", len(localIPv6Got), len(tt.wantLocalIPv6))
			}
			for i, b := range tt.wantLocalIPv6 {
				if localIPv6Got[i] != b {
					t.Errorf("localIPv6Address[%d] = %d, want %d", i, localIPv6Got[i], b)
				}
			}
			if typeGSeg.GetRemoteInterfaceID() != tt.wantRemoteIfaceID {
				t.Errorf("RemoteInterfaceID = %d, want %d", typeGSeg.GetRemoteInterfaceID(), tt.wantRemoteIfaceID)
			}
			remoteIPv6Got := typeGSeg.GetRemoteIPv6Address()
			if len(remoteIPv6Got) != len(tt.wantRemoteIPv6) {
				t.Fatalf("remoteIPv6Address length = %d, want %d", len(remoteIPv6Got), len(tt.wantRemoteIPv6))
			}
			for i, b := range tt.wantRemoteIPv6 {
				if remoteIPv6Got[i] != b {
					t.Errorf("remoteIPv6Address[%d] = %d, want %d", i, remoteIPv6Got[i], b)
				}
			}
			sid, hasSID := typeGSeg.GetSID()
			if tt.wantSID == nil {
				if hasSID {
					t.Error("Expected no SID, but got one")
				}
			} else {
				if !hasSID {
					t.Error("Expected SID, but got none")
				} else if sid != *tt.wantSID {
					t.Errorf("SID = %d, want %d", sid, *tt.wantSID)
				}
			}
		})
	}
}
func TestUnmarshalTypeHSegment_Valid(t *testing.T) {
	localIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	remoteIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	tests := []struct {
		name           string
		input          []byte
		wantLocalIPv6  []byte
		wantRemoteIPv6 []byte
		wantSID        *uint32
	}{
		{
			name:           "34 bytes no SID",
			input:          append(append([]byte{0x00, 0x00}, localIPv6...), remoteIPv6...),
			wantLocalIPv6:  localIPv6,
			wantRemoteIPv6: remoteIPv6,
			wantSID:        nil,
		},
		{
			name:           "38 bytes with SID",
			input:          append(append(append([]byte{0x00, 0x00}, localIPv6...), remoteIPv6...), []byte{0x00, 0x01, 0x86, 0xa0}...),
			wantLocalIPv6:  localIPv6,
			wantRemoteIPv6: remoteIPv6,
			wantSID:        ptrUint32(100000),
		},
		{
			name:           "flags set",
			input:          append(append([]byte{0xf0, 0x00}, localIPv6...), remoteIPv6...),
			wantLocalIPv6:  localIPv6,
			wantRemoteIPv6: remoteIPv6,
			wantSID:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalTypeHSegment(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalTypeHSegment() error = %v", err)
			}
			th, ok := result.(TypeHSegment)
			if !ok {
				t.Fatalf("result does not implement TypeHSegment")
			}
			localGot := th.GetLocalIPv6Address()
			if len(localGot) != len(tt.wantLocalIPv6) {
				t.Errorf("GetLocalIPv6Address() length = %d, want %d", len(localGot), len(tt.wantLocalIPv6))
			} else {
				for i := range tt.wantLocalIPv6 {
					if localGot[i] != tt.wantLocalIPv6[i] {
						t.Errorf("GetLocalIPv6Address() byte %d = %02x, want %02x", i, localGot[i], tt.wantLocalIPv6[i])
					}
				}
			}
			remoteGot := th.GetRemoteIPv6Address()
			if len(remoteGot) != len(tt.wantRemoteIPv6) {
				t.Errorf("GetRemoteIPv6Address() length = %d, want %d", len(remoteGot), len(tt.wantRemoteIPv6))
			} else {
				for i := range tt.wantRemoteIPv6 {
					if remoteGot[i] != tt.wantRemoteIPv6[i] {
						t.Errorf("GetRemoteIPv6Address() byte %d = %02x, want %02x", i, remoteGot[i], tt.wantRemoteIPv6[i])
					}
				}
			}
			sid, hasSID := th.GetSID()
			if tt.wantSID == nil {
				if hasSID {
					t.Errorf("GetSID() ok = true, want false")
				}
			} else {
				if !hasSID {
					t.Errorf("GetSID() ok = false, want true")
				} else if sid != *tt.wantSID {
					t.Errorf("GetSID() = %d, want %d", sid, *tt.wantSID)
				}
			}
		})
	}
}

func TestUnmarshalTypeHSegment_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"0 bytes", []byte{}},
		{"1 byte", []byte{0x00}},
		{"33 bytes", make([]byte, 33)},
		{"35 bytes", make([]byte, 35)},
		{"36 bytes", make([]byte, 36)},
		{"37 bytes", make([]byte, 37)},
		{"39 bytes", make([]byte, 39)},
		{"50 bytes", make([]byte, 50)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := UnmarshalTypeHSegment(tt.input); err == nil {
				t.Errorf("UnmarshalTypeHSegment() with %s input length %d, expected error but got none", tt.name, len(tt.input))
			}
		})
	}
}

func TestTypeHSegment_JSON(t *testing.T) {
	localIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	remoteIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	tests := []struct {
		name string
		seg  *typeHSegment
	}{
		{
			name: "no SID all flags false",
			seg: &typeHSegment{
				flags:             &SegmentFlags{Vflag: false, Aflag: false, Sflag: false, Bflag: false},
				localIPv6Address:  localIPv6,
				remoteIPv6Address: remoteIPv6,
			},
		},
		{
			name: "with SID all flags true",
			seg: &typeHSegment{
				flags:             &SegmentFlags{Vflag: true, Aflag: true, Sflag: true, Bflag: true},
				localIPv6Address:  localIPv6,
				remoteIPv6Address: remoteIPv6,
				sid:               ptrUint32(100000),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.seg)
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			var result typeHSegment
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if len(result.localIPv6Address) != len(tt.seg.localIPv6Address) {
				t.Errorf("localIPv6Address length = %d, want %d", len(result.localIPv6Address), len(tt.seg.localIPv6Address))
			} else {
				for i := range tt.seg.localIPv6Address {
					if result.localIPv6Address[i] != tt.seg.localIPv6Address[i] {
						t.Errorf("localIPv6Address byte %d = %02x, want %02x", i, result.localIPv6Address[i], tt.seg.localIPv6Address[i])
					}
				}
			}
			if len(result.remoteIPv6Address) != len(tt.seg.remoteIPv6Address) {
				t.Errorf("remoteIPv6Address length = %d, want %d", len(result.remoteIPv6Address), len(tt.seg.remoteIPv6Address))
			} else {
				for i := range tt.seg.remoteIPv6Address {
					if result.remoteIPv6Address[i] != tt.seg.remoteIPv6Address[i] {
						t.Errorf("remoteIPv6Address byte %d = %02x, want %02x", i, result.remoteIPv6Address[i], tt.seg.remoteIPv6Address[i])
					}
				}
			}
			if result.flags.Vflag != tt.seg.flags.Vflag {
				t.Errorf("Unmarshal() Vflag = %v, want %v", result.flags.Vflag, tt.seg.flags.Vflag)
			}
			if result.flags.Aflag != tt.seg.flags.Aflag {
				t.Errorf("Unmarshal() Aflag = %v, want %v", result.flags.Aflag, tt.seg.flags.Aflag)
			}
			if result.flags.Sflag != tt.seg.flags.Sflag {
				t.Errorf("Unmarshal() Sflag = %v, want %v", result.flags.Sflag, tt.seg.flags.Sflag)
			}
			if result.flags.Bflag != tt.seg.flags.Bflag {
				t.Errorf("Unmarshal() Bflag = %v, want %v", result.flags.Bflag, tt.seg.flags.Bflag)
			}
			if tt.seg.sid == nil {
				if result.sid != nil {
					t.Errorf("sid = %v, want nil", result.sid)
				}
			} else {
				if result.sid == nil || *result.sid != *tt.seg.sid {
					t.Errorf("sid = %v, want %v", result.sid, tt.seg.sid)
				}
			}
		})
	}
}

func TestUnmarshalSegmentListSTLV_TypeH(t *testing.T) {
	localIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	remoteIPv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	tests := []struct {
		name           string
		stlvBytes      []byte
		wantLocalIPv6  []byte
		wantRemoteIPv6 []byte
		wantSID        *uint32
	}{
		{
			name:           "single TypeH STLV no SID",
			stlvBytes:      append(append([]byte{byte(TypeH), 34}, []byte{0x00, 0x00}...), append(localIPv6, remoteIPv6...)...),
			wantLocalIPv6:  localIPv6,
			wantRemoteIPv6: remoteIPv6,
			wantSID:        nil,
		},
		{
			name:           "single TypeH STLV with SID",
			stlvBytes:      append(append([]byte{byte(TypeH), 38}, []byte{0x00, 0x00}...), append(append(localIPv6, remoteIPv6...), []byte{0x00, 0x01, 0x86, 0xa0}...)...),
			wantLocalIPv6:  localIPv6,
			wantRemoteIPv6: remoteIPv6,
			wantSID:        ptrUint32(100000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSegmentListSTLV(tt.stlvBytes)
			if err != nil {
				t.Fatalf("UnmarshalSegmentListSTLV() error = %v", err)
			}
			if len(result.Segment) != 1 {
				t.Fatalf("Segment count = %d, want 1", len(result.Segment))
			}
			typeHSeg, ok := result.Segment[0].(TypeHSegment)
			if !ok {
				t.Fatal("Segment is not TypeHSegment")
			}
			localGot := typeHSeg.GetLocalIPv6Address()
			if len(localGot) != len(tt.wantLocalIPv6) {
				t.Fatalf("localIPv6Address length = %d, want %d", len(localGot), len(tt.wantLocalIPv6))
			}
			for i, b := range tt.wantLocalIPv6 {
				if localGot[i] != b {
					t.Errorf("localIPv6Address[%d] = %02x, want %02x", i, localGot[i], b)
				}
			}
			remoteGot := typeHSeg.GetRemoteIPv6Address()
			if len(remoteGot) != len(tt.wantRemoteIPv6) {
				t.Fatalf("remoteIPv6Address length = %d, want %d", len(remoteGot), len(tt.wantRemoteIPv6))
			}
			for i, b := range tt.wantRemoteIPv6 {
				if remoteGot[i] != b {
					t.Errorf("remoteIPv6Address[%d] = %02x, want %02x", i, remoteGot[i], b)
				}
			}
			sid, hasSID := typeHSeg.GetSID()
			if tt.wantSID == nil {
				if hasSID {
					t.Error("Expected no SID, but got one")
				}
			} else {
				if !hasSID {
					t.Error("Expected SID, but got none")
				} else if sid != *tt.wantSID {
					t.Errorf("SID = %d, want %d", sid, *tt.wantSID)
				}
			}
		})
	}
}
// Type I Tests (IPv6 node address + SR Algorithm + optional SRv6 SID)
// =============================================================================

func TestUnmarshalTypeISegment_Valid(t *testing.T) {
	ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	srv6SID := []byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	// 22 bytes = flags(1) + algo(1) + ipv6(16) + SRv6 Endpoint Behavior(2) + Behavior Flags(1) + Reserved(1)
	base22 := append(append([]byte{0x00, 0x01}, ipv6...), []byte{0x00, 0x00, 0x00, 0x00}...)
	// 38 bytes = base22 + srv6SID(16)
	base38 := append(append([]byte(nil), base22...), srv6SID...)
	tests := []struct {
		name        string
		input       []byte
		wantAlgo    byte
		wantIPv6    []byte
		wantSRv6SID []byte
	}{
		{
			name:        "22 bytes no SID",
			input:       base22,
			wantAlgo:    0x01,
			wantIPv6:    ipv6,
			wantSRv6SID: nil,
		},
		{
			name:        "38 bytes with SRv6 SID",
			input:       base38,
			wantAlgo:    0x01,
			wantIPv6:    ipv6,
			wantSRv6SID: srv6SID,
		},
		{
			name:        "flags set",
			input:       append(append([]byte{0xf0, 0x00}, ipv6...), []byte{0x00, 0x00, 0x00, 0x00}...),
			wantAlgo:    0x00,
			wantIPv6:    ipv6,
			wantSRv6SID: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalTypeISegment(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalTypeISegment() error = %v", err)
			}
			ti, ok := result.(TypeISegment)
			if !ok {
				t.Fatalf("result does not implement TypeISegment")
			}
			if ti.GetSRAlgorithm() != tt.wantAlgo {
				t.Errorf("GetSRAlgorithm() = %d, want %d", ti.GetSRAlgorithm(), tt.wantAlgo)
			}
			ipv6Got := ti.GetIPv6NodeAddress()
			if len(ipv6Got) != len(tt.wantIPv6) {
				t.Errorf("GetIPv6NodeAddress() length = %d, want %d", len(ipv6Got), len(tt.wantIPv6))
			} else {
				for i := range tt.wantIPv6 {
					if ipv6Got[i] != tt.wantIPv6[i] {
						t.Errorf("GetIPv6NodeAddress() byte %d = %02x, want %02x", i, ipv6Got[i], tt.wantIPv6[i])
					}
				}
			}
			sid, hasSID := ti.GetSRv6SID()
			if tt.wantSRv6SID == nil {
				if hasSID {
					t.Errorf("GetSRv6SID() ok = true, want false")
				}
			} else {
				if !hasSID {
					t.Errorf("GetSRv6SID() ok = false, want true")
				} else {
					for i := range tt.wantSRv6SID {
						if sid[i] != tt.wantSRv6SID[i] {
							t.Errorf("GetSRv6SID() byte %d = %02x, want %02x", i, sid[i], tt.wantSRv6SID[i])
						}
					}
				}
			}
		})
	}
}

func TestUnmarshalTypeISegment_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"0 bytes", []byte{}},
		{"1 byte", []byte{0x00}},
		{"21 bytes", make([]byte, 21)},
		{"23 bytes", make([]byte, 23)},
		{"37 bytes", make([]byte, 37)},
		{"39 bytes", make([]byte, 39)},
		{"50 bytes", make([]byte, 50)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := UnmarshalTypeISegment(tt.input); err == nil {
				t.Errorf("UnmarshalTypeISegment() with %s input length %d, expected error but got none", tt.name, len(tt.input))
			}
		})
	}
}

func TestTypeISegment_JSON(t *testing.T) {
	ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	srv6SID := []byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	tests := []struct {
		name string
		seg  *typeISegment
	}{
		{
			name: "no SID all flags false",
			seg: &typeISegment{
				flags:           &SegmentFlags{Vflag: false, Aflag: false, Sflag: false, Bflag: false},
				srAlgorithm:     0,
				ipv6NodeAddress: ipv6,
			},
		},
		{
			name: "with SRv6 SID all flags true",
			seg: &typeISegment{
				flags:           &SegmentFlags{Vflag: true, Aflag: true, Sflag: true, Bflag: true},
				srAlgorithm:     1,
				ipv6NodeAddress: ipv6,
				srv6SID:         srv6SID,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.seg)
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			var result typeISegment
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if result.srAlgorithm != tt.seg.srAlgorithm {
				t.Errorf("srAlgorithm = %d, want %d", result.srAlgorithm, tt.seg.srAlgorithm)
			}
			if len(result.ipv6NodeAddress) != len(tt.seg.ipv6NodeAddress) {
				t.Errorf("ipv6NodeAddress length = %d, want %d", len(result.ipv6NodeAddress), len(tt.seg.ipv6NodeAddress))
			} else {
				for i := range tt.seg.ipv6NodeAddress {
					if result.ipv6NodeAddress[i] != tt.seg.ipv6NodeAddress[i] {
						t.Errorf("ipv6NodeAddress byte %d = %02x, want %02x", i, result.ipv6NodeAddress[i], tt.seg.ipv6NodeAddress[i])
					}
				}
			}
			if result.flags.Vflag != tt.seg.flags.Vflag {
				t.Errorf("Unmarshal() Vflag = %v, want %v", result.flags.Vflag, tt.seg.flags.Vflag)
			}
			if result.flags.Aflag != tt.seg.flags.Aflag {
				t.Errorf("Unmarshal() Aflag = %v, want %v", result.flags.Aflag, tt.seg.flags.Aflag)
			}
			if result.flags.Sflag != tt.seg.flags.Sflag {
				t.Errorf("Unmarshal() Sflag = %v, want %v", result.flags.Sflag, tt.seg.flags.Sflag)
			}
			if result.flags.Bflag != tt.seg.flags.Bflag {
				t.Errorf("Unmarshal() Bflag = %v, want %v", result.flags.Bflag, tt.seg.flags.Bflag)
			}
			if tt.seg.srv6SID == nil {
				if result.srv6SID != nil {
					t.Errorf("srv6SID = %v, want nil", result.srv6SID)
				}
			} else {
				if len(result.srv6SID) != len(tt.seg.srv6SID) {
					t.Errorf("srv6SID length = %d, want %d", len(result.srv6SID), len(tt.seg.srv6SID))
				} else {
					for i := range tt.seg.srv6SID {
						if result.srv6SID[i] != tt.seg.srv6SID[i] {
							t.Errorf("srv6SID byte %d = %02x, want %02x", i, result.srv6SID[i], tt.seg.srv6SID[i])
						}
					}
				}
			}
		})
	}
}

func TestUnmarshalSegmentListSTLV_TypeI(t *testing.T) {
	ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	// Type I STLV: type(1) + length(1) + flags(1) + algo(1) + ipv6(16) + SRv6 Endpoint Behavior(2) + Behavior Flags(1) + Reserved(1) = 24 bytes total, length field = 22
	stlv22 := append([]byte{byte(TypeI), 22, 0x00, 0x01}, append(ipv6, []byte{0x00, 0x00, 0x00, 0x00}...)...)
	tests := []struct {
		name      string
		stlvBytes []byte
		wantCount int
	}{
		{
			name:      "single TypeI STLV no SID",
			stlvBytes: stlv22,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSegmentListSTLV(tt.stlvBytes)
			if err != nil {
				t.Fatalf("UnmarshalSegmentListSTLV() error = %v", err)
			}
			if len(result.Segment) != tt.wantCount {
				t.Errorf("Segment count = %d, want %d", len(result.Segment), tt.wantCount)
			}
			if tt.wantCount > 0 {
				if result.Segment[0].GetType() != TypeI {
					t.Errorf("GetType() = %v, want TypeI", result.Segment[0].GetType())
				}
			}
		})
	}
}

// =============================================================================
// Type J Tests (IPv6 link-local adjacency with interface IDs + optional SRv6 SID)
// =============================================================================

func TestUnmarshalTypeJSegment_Valid(t *testing.T) {
	localIPv6 := []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	remoteIPv6 := []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	srv6SID := []byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	localIfaceID := []byte{0x00, 0x00, 0x00, 0x01}
	remoteIfaceID := []byte{0x00, 0x00, 0x00, 0x02}
	// 42 bytes: flags(1)+algo(1)+localIfaceID(4)+localIPv6(16)+remoteIfaceID(4)+remoteIPv6(16)
	base42 := append(append(append(append([]byte{0x00, 0x01}, localIfaceID...), localIPv6...), remoteIfaceID...), remoteIPv6...)
	tests := []struct {
		name              string
		input             []byte
		wantAlgo          byte
		wantLocalIfaceID  uint32
		wantLocalIPv6     []byte
		wantRemoteIfaceID uint32
		wantRemoteIPv6    []byte
		wantSRv6SID       []byte
	}{
		{
			name:              "42 bytes no SID",
			input:             base42,
			wantAlgo:          0x01,
			wantLocalIfaceID:  1,
			wantLocalIPv6:     localIPv6,
			wantRemoteIfaceID: 2,
			wantRemoteIPv6:    remoteIPv6,
			wantSRv6SID:       nil,
		},
		{
			name:              "58 bytes with SRv6 SID",
			input:             append(append([]byte(nil), base42...), srv6SID...),
			wantAlgo:          0x01,
			wantLocalIfaceID:  1,
			wantLocalIPv6:     localIPv6,
			wantRemoteIfaceID: 2,
			wantRemoteIPv6:    remoteIPv6,
			wantSRv6SID:       srv6SID,
		},
		{
			name:              "flags set",
			input:             append(append(append(append([]byte{0xf0, 0x00}, localIfaceID...), localIPv6...), remoteIfaceID...), remoteIPv6...),
			wantAlgo:          0x00,
			wantLocalIfaceID:  1,
			wantLocalIPv6:     localIPv6,
			wantRemoteIfaceID: 2,
			wantRemoteIPv6:    remoteIPv6,
			wantSRv6SID:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalTypeJSegment(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalTypeJSegment() error = %v", err)
			}
			tj, ok := result.(TypeJSegment)
			if !ok {
				t.Fatalf("result does not implement TypeJSegment")
			}
			if tj.GetSRAlgorithm() != tt.wantAlgo {
				t.Errorf("GetSRAlgorithm() = %d, want %d", tj.GetSRAlgorithm(), tt.wantAlgo)
			}
			if tj.GetLocalInterfaceID() != tt.wantLocalIfaceID {
				t.Errorf("GetLocalInterfaceID() = %d, want %d", tj.GetLocalInterfaceID(), tt.wantLocalIfaceID)
			}
			if tj.GetRemoteInterfaceID() != tt.wantRemoteIfaceID {
				t.Errorf("GetRemoteInterfaceID() = %d, want %d", tj.GetRemoteInterfaceID(), tt.wantRemoteIfaceID)
			}
			localGot := tj.GetLocalIPv6Address()
			if len(localGot) != len(tt.wantLocalIPv6) {
				t.Errorf("GetLocalIPv6Address() length = %d, want %d", len(localGot), len(tt.wantLocalIPv6))
			} else {
				for i := range tt.wantLocalIPv6 {
					if localGot[i] != tt.wantLocalIPv6[i] {
						t.Errorf("GetLocalIPv6Address() byte %d = %02x, want %02x", i, localGot[i], tt.wantLocalIPv6[i])
					}
				}
			}
			remoteGot := tj.GetRemoteIPv6Address()
			if len(remoteGot) != len(tt.wantRemoteIPv6) {
				t.Errorf("GetRemoteIPv6Address() length = %d, want %d", len(remoteGot), len(tt.wantRemoteIPv6))
			} else {
				for i := range tt.wantRemoteIPv6 {
					if remoteGot[i] != tt.wantRemoteIPv6[i] {
						t.Errorf("GetRemoteIPv6Address() byte %d = %02x, want %02x", i, remoteGot[i], tt.wantRemoteIPv6[i])
					}
				}
			}
			sid, hasSID := tj.GetSRv6SID()
			if tt.wantSRv6SID == nil {
				if hasSID {
					t.Errorf("GetSRv6SID() ok = true, want false")
				}
			} else {
				if !hasSID {
					t.Errorf("GetSRv6SID() ok = false, want true")
				} else if len(sid) != len(tt.wantSRv6SID) {
					t.Errorf("GetSRv6SID() length = %d, want %d", len(sid), len(tt.wantSRv6SID))
				} else {
					for i := range tt.wantSRv6SID {
						if sid[i] != tt.wantSRv6SID[i] {
							t.Errorf("GetSRv6SID() byte %d = %02x, want %02x", i, sid[i], tt.wantSRv6SID[i])
						}
					}
				}
			}
		})
	}
}

func TestUnmarshalTypeJSegment_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"0 bytes", []byte{}},
		{"1 byte", []byte{0x00}},
		{"41 bytes", make([]byte, 41)},
		{"43 bytes", make([]byte, 43)},
		{"57 bytes", make([]byte, 57)},
		{"59 bytes", make([]byte, 59)},
		{"70 bytes", make([]byte, 70)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := UnmarshalTypeJSegment(tt.input); err == nil {
				t.Errorf("UnmarshalTypeJSegment() with %s input length %d, expected error but got none", tt.name, len(tt.input))
			}
		})
	}
}

func TestTypeJSegment_JSON(t *testing.T) {
	localIPv6 := []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	remoteIPv6 := []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	srv6SID := []byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	tests := []struct {
		name string
		seg  *typeJSegment
	}{
		{
			name: "no SID all flags false",
			seg: &typeJSegment{
				flags:             &SegmentFlags{Vflag: false, Aflag: false, Sflag: false, Bflag: false},
				srAlgorithm:       0,
				localInterfaceID:  1,
				localIPv6Address:  localIPv6,
				remoteInterfaceID: 2,
				remoteIPv6Address: remoteIPv6,
			},
		},
		{
			name: "with SRv6 SID all flags true",
			seg: &typeJSegment{
				flags:             &SegmentFlags{Vflag: true, Aflag: true, Sflag: true, Bflag: true},
				srAlgorithm:       1,
				localInterfaceID:  100,
				localIPv6Address:  localIPv6,
				remoteInterfaceID: 200,
				remoteIPv6Address: remoteIPv6,
				srv6SID:           srv6SID,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.seg)
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			var result typeJSegment
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if result.srAlgorithm != tt.seg.srAlgorithm {
				t.Errorf("srAlgorithm = %d, want %d", result.srAlgorithm, tt.seg.srAlgorithm)
			}
			if result.localInterfaceID != tt.seg.localInterfaceID {
				t.Errorf("localInterfaceID = %d, want %d", result.localInterfaceID, tt.seg.localInterfaceID)
			}
			if result.remoteInterfaceID != tt.seg.remoteInterfaceID {
				t.Errorf("remoteInterfaceID = %d, want %d", result.remoteInterfaceID, tt.seg.remoteInterfaceID)
			}
			if len(result.localIPv6Address) != len(tt.seg.localIPv6Address) {
				t.Errorf("localIPv6Address length = %d, want %d", len(result.localIPv6Address), len(tt.seg.localIPv6Address))
			} else {
				for i := range tt.seg.localIPv6Address {
					if result.localIPv6Address[i] != tt.seg.localIPv6Address[i] {
						t.Errorf("localIPv6Address byte %d = %02x, want %02x", i, result.localIPv6Address[i], tt.seg.localIPv6Address[i])
					}
				}
			}
			if len(result.remoteIPv6Address) != len(tt.seg.remoteIPv6Address) {
				t.Errorf("remoteIPv6Address length = %d, want %d", len(result.remoteIPv6Address), len(tt.seg.remoteIPv6Address))
			} else {
				for i := range tt.seg.remoteIPv6Address {
					if result.remoteIPv6Address[i] != tt.seg.remoteIPv6Address[i] {
						t.Errorf("remoteIPv6Address byte %d = %02x, want %02x", i, result.remoteIPv6Address[i], tt.seg.remoteIPv6Address[i])
					}
				}
			}
			if result.flags.Vflag != tt.seg.flags.Vflag {
				t.Errorf("Unmarshal() Vflag = %v, want %v", result.flags.Vflag, tt.seg.flags.Vflag)
			}
			if result.flags.Aflag != tt.seg.flags.Aflag {
				t.Errorf("Unmarshal() Aflag = %v, want %v", result.flags.Aflag, tt.seg.flags.Aflag)
			}
			if result.flags.Sflag != tt.seg.flags.Sflag {
				t.Errorf("Unmarshal() Sflag = %v, want %v", result.flags.Sflag, tt.seg.flags.Sflag)
			}
			if result.flags.Bflag != tt.seg.flags.Bflag {
				t.Errorf("Unmarshal() Bflag = %v, want %v", result.flags.Bflag, tt.seg.flags.Bflag)
			}
			if tt.seg.srv6SID == nil {
				if result.srv6SID != nil {
					t.Errorf("srv6SID = %v, want nil", result.srv6SID)
				}
			} else if len(result.srv6SID) != len(tt.seg.srv6SID) {
				t.Errorf("srv6SID length = %d, want %d", len(result.srv6SID), len(tt.seg.srv6SID))
			} else {
				for i := range tt.seg.srv6SID {
					if result.srv6SID[i] != tt.seg.srv6SID[i] {
						t.Errorf("srv6SID byte %d = %02x, want %02x", i, result.srv6SID[i], tt.seg.srv6SID[i])
					}
				}
			}
		})
	}
}

func TestUnmarshalSegmentListSTLV_TypeJ(t *testing.T) {
	localIPv6 := []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	remoteIPv6 := []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	localIfaceID := []byte{0x00, 0x00, 0x00, 0x01}
	remoteIfaceID := []byte{0x00, 0x00, 0x00, 0x02}
	srv6SID := []byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	payload42 := append(append(append(append([]byte{0x00, 0x01}, localIfaceID...), localIPv6...), remoteIfaceID...), remoteIPv6...)
	payload58 := append(append(payload42, srv6SID...), []byte{}...)
	tests := []struct {
		name      string
		stlvBytes []byte
		wantCount int
	}{
		{
			name:      "single TypeJ STLV no SID",
			stlvBytes: append([]byte{byte(TypeJ), 42}, payload42...),
			wantCount: 1,
		},
		{
			name:      "single TypeJ STLV with SRv6 SID",
			stlvBytes: append([]byte{byte(TypeJ), 58}, payload58...),
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSegmentListSTLV(tt.stlvBytes)
			if err != nil {
				t.Fatalf("UnmarshalSegmentListSTLV() error = %v", err)
			}
			if len(result.Segment) != tt.wantCount {
				t.Errorf("Segment count = %d, want %d", len(result.Segment), tt.wantCount)
			}
			if tt.wantCount > 0 && result.Segment[0].GetType() != TypeJ {
				t.Errorf("GetType() = %v, want TypeJ", result.Segment[0].GetType())
			}
		})
	}
}
