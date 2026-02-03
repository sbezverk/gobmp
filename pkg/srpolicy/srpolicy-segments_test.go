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
