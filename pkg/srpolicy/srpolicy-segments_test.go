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
		name string
		sid  []byte
	}{
		{
			name: "Standard SRv6 SID",
			sid: []byte{
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
		},
		{
			name: "All zeros",
			sid:  make([]byte, 16),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg := &typeBSegment{
				flags: NewSegmentFlags(0x00),
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

			// Verify SID
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := UnmarshalTypeCSegment(tt.input)
			if err != nil {
				t.Errorf("UnmarshalTypeCSegment() error = %v", err)
				return
			}

			typeCSegg, ok := seg.(TypeCSegment)
			if !ok {
				t.Error("Segment is not TypeCSegment")
				return
			}

			ipv4 := typeCSegg.GetIPv4Address()
			if len(ipv4) != 4 {
				t.Errorf("IPv4 address length = %d, want 4", len(ipv4))
				return
			}

			for i, b := range tt.wantIPv4 {
				if ipv4[i] != b {
					t.Errorf("IPv4 byte %d = %d, want %d", i, ipv4[i], b)
				}
			}

			if typeCSegg.GetSRAlgorithm() != tt.wantAlgo {
				t.Errorf("SR Algorithm = %d, want %d", typeCSegg.GetSRAlgorithm(), tt.wantAlgo)
			}

			sid, hasSID := typeCSegg.GetSID()
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
