package srpolicy

import (
	"encoding/binary"
	"flag"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalSRPolicyTLV(t *testing.T) {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	tests := []struct {
		name   string
		input  []byte
		expect *TLV
		fail   bool
	}{
		{
			name:  "valid label sr policy",
			input: []byte{0x00, 0x0F, 0x00, 0x48, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x0D, 0x06, 0x00, 0x00, 0xDB, 0xBA, 0x00, 0x00, 0x80, 0x00, 0x19, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x18, 0x6A, 0xA0, 0x00, 0x01, 0x06, 0x00, 0x00, 0x05, 0xDC, 0x10, 0x00, 0x80, 0x00, 0x19, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x06, 0x00, 0x00, 0x18, 0x6A, 0xA0, 0x00, 0x01, 0x06, 0x00, 0x00, 0x05, 0xDC, 0xD0, 0x00},
			expect: &TLV{
				Preference: &Preference{
					Flags:      0x0,
					Preference: 0x44,
				},
				BindingSID: &BindingSID{
					Type: LABELBSID,
					BSID: &labelBSID{
						flags: 0x0,
						bsid:  binary.BigEndian.Uint32([]byte{0xDB, 0xBA, 0x00, 0x00}),
					},
				},
				SegmentList: []*SegmentList{
					{
						Weight: &Weight{
							Flags:  0,
							Weight: 1,
						},
						Segment: []Segment{
							&typeASegment{
								flags: &SegmentFlags{
									Vflag: false,
									Aflag: false,
									Sflag: false,
									Bflag: false,
								},
								label: 100010,
								tc:    0,
								s:     false,
								ttl:   0,
							},
							&typeASegment{
								flags: &SegmentFlags{
									Vflag: false,
									Aflag: false,
									Sflag: false,
									Bflag: false,
								},
								label: 24001,
								tc:    0,
								s:     false,
								ttl:   0,
							},
						},
					},
					{
						Weight: &Weight{
							Flags:  0,
							Weight: 3,
						},
						Segment: []Segment{
							&typeASegment{
								flags: &SegmentFlags{
									Vflag: false,
									Aflag: false,
									Sflag: false,
									Bflag: false,
								},
								label: 100010,
								tc:    0,
								s:     false,
								ttl:   0,
							},
							&typeASegment{
								flags: &SegmentFlags{
									Vflag: false,
									Aflag: false,
									Sflag: false,
									Bflag: false,
								},
								label: 24013,
								tc:    0,
								s:     false,
								ttl:   0,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRPolicyTLV(tt.input)
			if err != nil && !tt.fail {
				t.Fatalf("Supposed to succeed but failed with error: %+v", err)
				return
			}
			if err == nil && tt.fail {
				t.Fatalf("Supposed to fail but succeeded")
				return
			}
			if err != nil {
				return
			}
			if got == nil {
				t.Fatalf("processed TLV is nil")
			}
			//			if !reflect.DeepEqual(tt.expect, got) {
			for i := 0; i < len(got.SegmentList); i++ {
				t.Logf("Weight got: %+v Weight expect: %+v", *got.SegmentList[i].Weight, tt.expect.SegmentList[i].Weight)
				for y := 0; y < len(got.SegmentList[i].Segment); y++ {
					t.Logf("Flags got: %+v Flags expect: %+v", *got.SegmentList[i].Segment[y].GetFlags(),
						tt.expect.SegmentList[i].Segment[y].GetFlags())
					t.Logf("Type got: %d Type expect: %d", got.SegmentList[i].Segment[y].GetType(),
						tt.expect.SegmentList[i].Segment[y].GetType())
					t.Logf("Interface diff: %+v", deep.Equal(got.SegmentList[i].Segment[y], tt.expect.SegmentList[i].Segment[y]))
					g := got.SegmentList[i].Segment[y].(*typeASegment)
					e := tt.expect.SegmentList[i].Segment[y]
					t.Logf("Structure diff: %+v", deep.Equal(g, e))
				}
			}
			//			t.Fatalf("Expected TLV: %+v does not match to the processed TLV: %+v", *tt.expect, *got)
			//			}
		})
	}
}

// ============================================================================
// Additional UnmarshalSRPolicyTLV Tests - Wire Format Parsing
// ============================================================================

func TestUnmarshalSRPolicyTLV_Empty(t *testing.T) {
	// MP_UNREACH case - no TLVs
	tlv, err := UnmarshalSRPolicyTLV([]byte{})
	if err != nil {
		t.Errorf("UnmarshalSRPolicyTLV() error = %v", err)
		return
	}
	if tlv != nil {
		t.Errorf("UnmarshalSRPolicyTLV() expected nil for empty input, got %v", tlv)
	}
}

func TestUnmarshalSRPolicyTLV_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "1 byte",
			input: []byte{0x00},
		},
		{
			name:  "2 bytes",
			input: []byte{0x00, 0x00},
		},
		{
			name:  "3 bytes",
			input: []byte{0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalSRPolicyTLV(tt.input)
			if err == nil {
				t.Error("UnmarshalSRPolicyTLV() expected error for invalid length, got nil")
			}
		})
	}
}

func TestUnmarshalSRPolicyTLV_InvalidTunnelType(t *testing.T) {
	// Invalid tunnel type (not 15)
	input := []byte{
		0x00, 0x10, // Tunnel Type: 16 (INVALID, should be 15)
		0x00, 0x00, // Length: 0
	}

	_, err := UnmarshalSRPolicyTLV(input)
	if err == nil {
		t.Error("UnmarshalSRPolicyTLV() expected error for invalid tunnel type, got nil")
	}
}

func TestUnmarshalSRPolicyTLV_LengthMismatch(t *testing.T) {
	// Length field doesn't match actual data
	input := []byte{
		0x00, 0x0F, // Tunnel Type: 15 (correct)
		0x00, 0x0A, // Length: 10 (but no data follows)
	}

	_, err := UnmarshalSRPolicyTLV(input)
	if err == nil {
		t.Error("UnmarshalSRPolicyTLV() expected error for length mismatch, got nil")
	}
}

func TestUnmarshalSRPolicyTLV_BSID(t *testing.T) {
	// SR Policy TLV with BSID Sub-TLV
	input := []byte{
		0x00, 0x0F, // Tunnel Type: 15 (SR Policy)
		0x00, 0x04, // Length: 4 bytes (1 type + 1 length + 2 BSID data)
		0x0D,       // Sub-TLV Type: BSID (13)
		0x02,       // Sub-TLV Length: 2 bytes
		0x01, 0x00, // noBSID: flags=0x01, reserved=0x00
	}

	tlv, err := UnmarshalSRPolicyTLV(input)
	if err != nil {
		t.Errorf("UnmarshalSRPolicyTLV() error = %v", err)
		return
	}

	if tlv.BindingSID == nil {
		t.Error("UnmarshalSRPolicyTLV() BindingSID is nil")
		return
	}
	if tlv.BindingSID.Type != NOBSID {
		t.Errorf("UnmarshalSRPolicyTLV() BindingSID type = %v, want NOBSID", tlv.BindingSID.Type)
	}
	if tlv.BindingSID.BSID.GetFlag() != 0x01 {
		t.Errorf("UnmarshalSRPolicyTLV() BindingSID flags = %v, want 0x01", tlv.BindingSID.BSID.GetFlag())
	}
}

// ============================================================================
// ENLP Sub-TLV Tests (RFC 9830)
// ============================================================================

func TestUnmarshalSRPolicyTLV_ENLP(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantFlags byte
		wantENLP  byte
		wantErr   bool
	}{
		{
			name: "ENLP value 1",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15 (SR Policy)
				0x00, 0x06, // Length: 6 bytes
				0x0E,       // Sub-TLV Type: ENLP (14)
				0x04,       // Sub-TLV Length: 4 bytes
				0x01,       // Flags
				0x00,       // Reserved
				0x01,       // ENLP value
				0x00,       // Reserved
			},
			wantFlags: 0x01,
			wantENLP:  0x01,
			wantErr:   false,
		},
		{
			name: "ENLP value 2",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x06, // Length: 6 bytes
				0x0E,       // Sub-TLV Type: ENLP (14)
				0x04,       // Length: 4 bytes
				0x00,       // Flags
				0x00,       // Reserved
				0x02,       // ENLP value: 2
				0x00,       // Reserved
			},
			wantFlags: 0x00,
			wantENLP:  0x02,
			wantErr:   false,
		},
		{
			name: "ENLP all zeros",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x06, // Length: 6 bytes
				0x0E,       // Sub-TLV Type: ENLP (14)
				0x04,       // Length: 4 bytes
				0x00,       // Flags
				0x00,       // Reserved
				0x00,       // ENLP value: 0
				0x00,       // Reserved
			},
			wantFlags: 0x00,
			wantENLP:  0x00,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlv, err := UnmarshalSRPolicyTLV(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalSRPolicyTLV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if tlv.ENLP == nil {
				t.Error("UnmarshalSRPolicyTLV() ENLP is nil")
				return
			}

			if tlv.ENLP.Flags != tt.wantFlags {
				t.Errorf("UnmarshalSRPolicyTLV() ENLP.Flags = %v, want %v", tlv.ENLP.Flags, tt.wantFlags)
			}
			if tlv.ENLP.ENLP != tt.wantENLP {
				t.Errorf("UnmarshalSRPolicyTLV() ENLP.ENLP = %v, want %v", tlv.ENLP.ENLP, tt.wantENLP)
			}
		})
	}
}

func TestUnmarshalSRPolicyTLV_DuplicateENLP(t *testing.T) {
	// Duplicate ENLP sub-TLVs - only 1 instance allowed per RFC 9830
	input := []byte{
		0x00, 0x0F, // Tunnel Type: 15
		0x00, 0x0C, // Length: 12 bytes (2 ENLP sub-TLVs)
		0x0E,       // Sub-TLV Type: ENLP (14)
		0x04,       // Length: 4 bytes
		0x01,       // Flags
		0x00,       // Reserved
		0x01,       // ENLP value
		0x00,       // Reserved
		0x0E,       // Sub-TLV Type: ENLP (14) - DUPLICATE
		0x04,       // Length: 4 bytes
		0x01,       // Flags
		0x00,       // Reserved
		0x02,       // ENLP value
		0x00,       // Reserved
	}

	_, err := UnmarshalSRPolicyTLV(input)
	if err == nil {
		t.Error("UnmarshalSRPolicyTLV() expected error for duplicate ENLP, got nil")
	}
}

// ============================================================================
// Priority Sub-TLV Tests (RFC 9830)
// ============================================================================

func TestUnmarshalSRPolicyTLV_Priority(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		wantPriority byte
	}{
		{
			name: "Priority 100",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x03, // Length: 3 bytes
				0x0F,       // Sub-TLV Type: Priority (15)
				0x01,       // Length: 1 byte
				0x64,       // Priority: 100
			},
			wantPriority: 100,
		},
		{
			name: "Priority 0",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x03, // Length: 3 bytes
				0x0F,       // Sub-TLV Type: Priority (15)
				0x01,       // Length: 1 byte
				0x00,       // Priority: 0
			},
			wantPriority: 0,
		},
		{
			name: "Priority 255 (max)",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x03, // Length: 3 bytes
				0x0F,       // Sub-TLV Type: Priority (15)
				0x01,       // Length: 1 byte
				0xFF,       // Priority: 255
			},
			wantPriority: 255,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlv, err := UnmarshalSRPolicyTLV(tt.input)
			if err != nil {
				t.Errorf("UnmarshalSRPolicyTLV() error = %v", err)
				return
			}

			if tlv.Priority != tt.wantPriority {
				t.Errorf("UnmarshalSRPolicyTLV() Priority = %v, want %v", tlv.Priority, tt.wantPriority)
			}
		})
	}
}

// ============================================================================
// PathName Sub-TLV Tests (RFC 9830)
// ============================================================================

func TestUnmarshalSRPolicyTLV_PathName(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		wantPathName string
	}{
		{
			name: "PathName 'primary-path'",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x0E, // Length: 14 bytes
				0x81,       // Sub-TLV Type: PathName (129)
				0x0C,       // Length: 12 bytes
				// "primary-path"
				0x70, 0x72, 0x69, 0x6D, 0x61, 0x72, 0x79, 0x2D, 0x70, 0x61, 0x74, 0x68,
			},
			wantPathName: "primary-path",
		},
		{
			name: "PathName 'backup'",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x08, // Length: 8 bytes
				0x81,       // Sub-TLV Type: PathName (129)
				0x06,       // Length: 6 bytes
				// "backup"
				0x62, 0x61, 0x63, 0x6B, 0x75, 0x70,
			},
			wantPathName: "backup",
		},
		{
			name: "PathName single char 'A'",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x03, // Length: 3 bytes
				0x81,       // Sub-TLV Type: PathName (129)
				0x01,       // Length: 1 byte
				0x41,       // "A"
			},
			wantPathName: "A",
		},
		{
			name: "PathName empty",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x02, // Length: 2 bytes
				0x81,       // Sub-TLV Type: PathName (129)
				0x00,       // Length: 0 bytes
			},
			wantPathName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlv, err := UnmarshalSRPolicyTLV(tt.input)
			if err != nil {
				t.Errorf("UnmarshalSRPolicyTLV() error = %v", err)
				return
			}

			if tlv.PathName != tt.wantPathName {
				t.Errorf("UnmarshalSRPolicyTLV() PathName = %v, want %v", tlv.PathName, tt.wantPathName)
			}
		})
	}
}

// ============================================================================
// Unknown Sub-TLV Handling Tests
// ============================================================================

func TestUnmarshalSRPolicyTLV_UnknownSubTLV(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name: "Unknown sub-TLV 200 - should skip gracefully",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x06, // Length: 6 bytes
				0xC8,       // Sub-TLV Type: 200 (unknown)
				0x04,       // Length: 4 bytes
				0x01, 0x02, 0x03, 0x04, // Data
			},
			wantErr: false, // Should skip unknown sub-TLVs
		},
		{
			name: "Unknown sub-TLV 99 with zero length",
			input: []byte{
				0x00, 0x0F, // Tunnel Type: 15
				0x00, 0x02, // Length: 2 bytes
				0x63,       // Sub-TLV Type: 99 (unknown)
				0x00,       // Length: 0 bytes
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlv, err := UnmarshalSRPolicyTLV(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalSRPolicyTLV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && tlv == nil {
				t.Error("UnmarshalSRPolicyTLV() returned nil TLV without error")
			}
		})
	}
}

// ============================================================================
// Sub-TLV Combination Tests
// ============================================================================

func TestUnmarshalSRPolicyTLV_MultipleSubTLVs(t *testing.T) {
	// Preference + BSID + ENLP + Priority + PathName
	input := []byte{
		0x00, 0x0F, // Tunnel Type: 15
		0x00, 0x1B, // Length: 27 bytes

		// Preference sub-TLV
		0x0C,                   // Type: Preference (12)
		0x06,                   // Length: 6 bytes
		0x01,                   // Flags
		0x00,                   // Reserved
		0x00, 0x00, 0x00, 0x64, // Preference: 100

		// Binding SID sub-TLV (noBSID)
		0x0D,       // Type: BSID (13)
		0x02,       // Length: 2 bytes
		0x01, 0x00, // noBSID

		// ENLP sub-TLV
		0x0E,             // Type: ENLP (14)
		0x04,             // Length: 4 bytes
		0x00,             // Flags
		0x00,             // Reserved
		0x01,             // ENLP value
		0x00,             // Reserved

		// Priority sub-TLV
		0x0F, // Type: Priority (15)
		0x01, // Length: 1 byte
		0x32, // Priority: 50

		// PathName sub-TLV
		0x81,       // Type: PathName (129)
		0x04,       // Length: 4 bytes
		0x6D, 0x61, 0x69, 0x6E, // "main"
	}

	tlv, err := UnmarshalSRPolicyTLV(input)
	if err != nil {
		t.Errorf("UnmarshalSRPolicyTLV() error = %v", err)
		return
	}

	// Verify Preference
	if tlv.Preference == nil {
		t.Error("UnmarshalSRPolicyTLV() Preference is nil")
	} else {
		if tlv.Preference.Preference != 100 {
			t.Errorf("Preference = %v, want 100", tlv.Preference.Preference)
		}
	}

	// Verify BSID
	if tlv.BindingSID == nil {
		t.Error("UnmarshalSRPolicyTLV() BindingSID is nil")
	} else {
		if tlv.BindingSID.Type != NOBSID {
			t.Errorf("BSID type = %v, want NOBSID", tlv.BindingSID.Type)
		}
	}

	// Verify ENLP
	if tlv.ENLP == nil {
		t.Error("UnmarshalSRPolicyTLV() ENLP is nil")
	} else {
		if tlv.ENLP.ENLP != 1 {
			t.Errorf("ENLP = %v, want 1", tlv.ENLP.ENLP)
		}
	}

	// Verify Priority
	if tlv.Priority != 50 {
		t.Errorf("Priority = %v, want 50", tlv.Priority)
	}

	// Verify PathName
	if tlv.PathName != "main" {
		t.Errorf("PathName = %v, want 'main'", tlv.PathName)
	}
}

func TestUnmarshalSRPolicyTLV_MinimalValid(t *testing.T) {
	// Only Preference (required in practice, though not enforced by parser)
	input := []byte{
		0x00, 0x0F, // Tunnel Type: 15
		0x00, 0x08, // Length: 8 bytes
		0x0C,                   // Type: Preference (12)
		0x06,                   // Length: 6 bytes
		0x00,                   // Flags
		0x00,                   // Reserved
		0x00, 0x00, 0x00, 0x01, // Preference: 1
	}

	tlv, err := UnmarshalSRPolicyTLV(input)
	if err != nil {
		t.Errorf("UnmarshalSRPolicyTLV() error = %v", err)
		return
	}

	if tlv.Preference == nil {
		t.Error("UnmarshalSRPolicyTLV() Preference is nil")
		return
	}

	if tlv.Preference.Preference != 1 {
		t.Errorf("Preference = %v, want 1", tlv.Preference.Preference)
	}

	// Verify other sub-TLVs are nil/empty
	if tlv.BindingSID != nil {
		t.Error("Expected BindingSID to be nil")
	}
	if tlv.ENLP != nil {
		t.Error("Expected ENLP to be nil")
	}
	if tlv.Priority != 0 {
		t.Errorf("Expected Priority to be 0, got %v", tlv.Priority)
	}
	if tlv.PathName != "" {
		t.Errorf("Expected PathName to be empty, got %v", tlv.PathName)
	}
	if len(tlv.SegmentList) != 0 {
		t.Errorf("Expected empty SegmentList, got %v items", len(tlv.SegmentList))
	}
}
