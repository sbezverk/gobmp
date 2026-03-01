package bgpls

import (
	"testing"
)

// TestGetSRBindingSID verifies GetSRBindingSID parses TLV type 1201 from NLRI.
func TestGetSRBindingSID(t *testing.T) {
	// 4-byte flags+reserved + 4-byte MPLS SID (FlagD clear = MPLS, FlagU clear = PSID present)
	// flags byte: FlagB set (0x40), FlagU clear → PSID present
	// So: flags=0x40, reserved=0x00, reserved2=0x00,0x00, BSID=4 bytes, PSID=4 bytes → total 12 bytes
	flags := byte(0x40) // FlagB set, FlagD clear (MPLS), FlagU clear
	bsidLabel := []byte{0x00, 0x10, 0x00, 0x00} // label 16
	psidLabel := []byte{0x00, 0x20, 0x00, 0x00} // label 32
	value := append([]byte{flags, 0x00, 0x00, 0x00}, bsidLabel...)
	value = append(value, psidLabel...)

	nlri := &NLRI{
		LS: []TLV{
			{Type: BindingSIDType, Length: uint16(len(value)), Value: value},
		},
	}

	got, err := nlri.GetSRBindingSID()
	if err != nil {
		t.Fatalf("GetSRBindingSID() error = %v", err)
	}
	if got.FlagB != true {
		t.Errorf("FlagB = false, want true")
	}
	if got.FlagD != false {
		t.Errorf("FlagD = true, want false")
	}
}

// TestGetSRBindingSID_NotFound verifies GetSRBindingSID returns error when TLV absent.
func TestGetSRBindingSID_NotFound(t *testing.T) {
	nlri := &NLRI{LS: []TLV{}}
	_, err := nlri.GetSRBindingSID()
	if err == nil {
		t.Error("GetSRBindingSID() expected error for empty NLRI, got nil")
	}
}

// TestGetSRCandidatePathState verifies GetSRCandidatePathState parses TLV type 1202.
func TestGetSRCandidatePathState(t *testing.T) {
	// 8-byte fixed: priority(1), reserved(1), flags(1), flags2(1), preference(4)
	// flags byte: FlagA (0x40), FlagV (0x08)
	value := []byte{
		0x05,       // Priority = 5
		0x00,       // reserved
		0x40 | 0x08, // FlagA=1, FlagV=1
		0x00,       // flags2
		0x00, 0x00, 0x00, 0x64, // Preference = 100
	}

	nlri := &NLRI{
		LS: []TLV{
			{Type: SRCandidatePathStateType, Length: uint16(len(value)), Value: value},
		},
	}

	got, err := nlri.GetSRCandidatePathState()
	if err != nil {
		t.Fatalf("GetSRCandidatePathState() error = %v", err)
	}
	if got.Priority != 5 {
		t.Errorf("Priority = %d, want 5", got.Priority)
	}
	if got.FlagA != true {
		t.Errorf("FlagA = false, want true")
	}
	if got.FlagV != true {
		t.Errorf("FlagV = false, want true")
	}
	if got.Preference != 100 {
		t.Errorf("Preference = %d, want 100", got.Preference)
	}
}

// TestGetSRCandidatePathState_NotFound verifies error when TLV absent.
func TestGetSRCandidatePathState_NotFound(t *testing.T) {
	nlri := &NLRI{LS: []TLV{}}
	_, err := nlri.GetSRCandidatePathState()
	if err == nil {
		t.Error("GetSRCandidatePathState() expected error for empty NLRI, got nil")
	}
}

// TestGetSRCandidatePathName verifies GetSRCandidatePathName parses TLV type 1203.
func TestGetSRCandidatePathName(t *testing.T) {
	name := "test-policy"
	value := []byte(name)

	nlri := &NLRI{
		LS: []TLV{
			{Type: SRCandidatePathNameType, Length: uint16(len(value)), Value: value},
		},
	}

	got, err := nlri.GetSRCandidatePathName()
	if err != nil {
		t.Fatalf("GetSRCandidatePathName() error = %v", err)
	}
	if got.SymbolicName != name {
		t.Errorf("SymbolicName = %q, want %q", got.SymbolicName, name)
	}
}

// TestGetSRCandidatePathName_NotFound verifies error when TLV absent.
func TestGetSRCandidatePathName_NotFound(t *testing.T) {
	nlri := &NLRI{LS: []TLV{}}
	_, err := nlri.GetSRCandidatePathName()
	if err == nil {
		t.Error("GetSRCandidatePathName() expected error for empty NLRI, got nil")
	}
}

// TestGetSRCandidatePathConstraints verifies GetSRCandidatePathConstraints parses TLV type 1204.
func TestGetSRCandidatePathConstraints(t *testing.T) {
	// 8-byte fixed header: flags(1), reserved(1), MTID(2), algo(1), reserved(3)
	// Byte 0 flags: FlagD=0x80
	value := []byte{
		0x80,             // FlagD=1
		0x00,             // reserved
		0x00, 0x00,       // MTID = 0
		0x80,             // Algo = 128 (FlexAlgo 128)
		0x00, 0x00, 0x00, // 3 reserved bytes
	}

	nlri := &NLRI{
		LS: []TLV{
			{Type: SRCandidatePathConstraintsType, Length: uint16(len(value)), Value: value},
		},
	}

	got, err := nlri.GetSRCandidatePathConstraints()
	if err != nil {
		t.Fatalf("GetSRCandidatePathConstraints() error = %v", err)
	}
	if got.FlagD != true {
		t.Errorf("FlagD = false, want true")
	}
	if got.Algo != 0x80 {
		t.Errorf("Algo = %d, want 128", got.Algo)
	}
}

// TestGetSRCandidatePathConstraints_NotFound verifies error when TLV absent.
func TestGetSRCandidatePathConstraints_NotFound(t *testing.T) {
	nlri := &NLRI{LS: []TLV{}}
	_, err := nlri.GetSRCandidatePathConstraints()
	if err == nil {
		t.Error("GetSRCandidatePathConstraints() expected error for empty NLRI, got nil")
	}
}

// TestGetSRSegmentList verifies GetSRSegmentList parses TLV type 1205.
func TestGetSRSegmentList(t *testing.T) {
	// 12-byte minimum: reserved(1), flags(1), flags2(1), reserved(1), MTID(2), Algo(1), reserved(1), Weight(4)
	// flags byte at offset 1: all clear
	value := []byte{
		0x00,                   // reserved
		0x00,                   // flags byte
		0x00,                   // flags2 (FlagM)
		0x00,                   // reserved
		0x00, 0x00,             // MTID = 0
		0x00,                   // Algo = 0
		0x00,                   // reserved
		0x00, 0x00, 0x00, 0x0a, // Weight = 10
	}

	nlri := &NLRI{
		LS: []TLV{
			{Type: SRSegmentListType, Length: uint16(len(value)), Value: value},
		},
	}

	got, err := nlri.GetSRSegmentList()
	if err != nil {
		t.Fatalf("GetSRSegmentList() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("GetSRSegmentList() returned %d lists, want 1", len(got))
	}
	if got[0].Weight != 10 {
		t.Errorf("Weight = %d, want 10", got[0].Weight)
	}
}

// TestGetSRSegmentList_Multiple verifies multiple segment lists are returned.
func TestGetSRSegmentList_Multiple(t *testing.T) {
	value := []byte{
		0x00, 0x00, 0x00, 0x00, // reserved + flags
		0x00, 0x00,             // MTID
		0x00, 0x00,             // Algo + reserved
		0x00, 0x00, 0x00, 0x05, // Weight = 5
	}

	nlri := &NLRI{
		LS: []TLV{
			{Type: SRSegmentListType, Length: uint16(len(value)), Value: value},
			{Type: SRSegmentListType, Length: uint16(len(value)), Value: value},
		},
	}

	got, err := nlri.GetSRSegmentList()
	if err != nil {
		t.Fatalf("GetSRSegmentList() error = %v", err)
	}
	if len(got) != 2 {
		t.Errorf("GetSRSegmentList() returned %d lists, want 2", len(got))
	}
}

// TestGetSRSegmentList_Empty verifies empty slice returned when TLV absent.
func TestGetSRSegmentList_Empty(t *testing.T) {
	nlri := &NLRI{LS: []TLV{}}
	got, err := nlri.GetSRSegmentList()
	if err != nil {
		t.Fatalf("GetSRSegmentList() unexpected error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("GetSRSegmentList() returned %d lists, want 0", len(got))
	}
}
