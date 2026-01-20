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
