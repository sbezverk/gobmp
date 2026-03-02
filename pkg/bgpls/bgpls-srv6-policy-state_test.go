package bgpls

import (
	"encoding/binary"
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

// buildSegmentBytes constructs the 4-byte SR Segment header [type, reserved, flagHi, flagLo]
// with optional SID bytes appended. FlagS (0x80 in flagHi) signals a SID is present.
func buildSegmentBytes(segType SegmentType, flagHi byte, sid []byte) []byte {
	b := []byte{byte(segType), 0x00, flagHi, 0x00}
	return append(b, sid...)
}

// TestUnmarshalSRSegment_Type1_WithSID verifies SegmentType1 parses an MPLS Label SID.
func TestUnmarshalSRSegment_Type1_WithSID(t *testing.T) {
	label := uint32(100) << 12
	sid := make([]byte, 4)
	binary.BigEndian.PutUint32(sid, label)
	b := buildSegmentBytes(SegmentType1, 0x80, sid)

	seg, err := UnmarshalSRSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalSRSegment Type1: %v", err)
	}
	s := seg.(*SRSegment)
	if s.Segment != SegmentType1 {
		t.Errorf("Segment = %d, want %d", s.Segment, SegmentType1)
	}
	if !s.FlagS {
		t.Error("FlagS = false, want true")
	}
}

// TestUnmarshalSRSegment_Type3_WithSID verifies SegmentType3 parses an MPLS Label SID.
func TestUnmarshalSRSegment_Type3_WithSID(t *testing.T) {
	label := uint32(200) << 12
	sid := make([]byte, 4)
	binary.BigEndian.PutUint32(sid, label)
	b := buildSegmentBytes(SegmentType3, 0x80, sid)

	seg, err := UnmarshalSRSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalSRSegment Type3: %v", err)
	}
	s := seg.(*SRSegment)
	if s.Segment != SegmentType3 {
		t.Errorf("Segment = %d, want %d", s.Segment, SegmentType3)
	}
}

// TestUnmarshalSRSegment_Type9_WithSID verifies SegmentType9 parses an SRv6 (IPv6) SID.
func TestUnmarshalSRSegment_Type9_WithSID(t *testing.T) {
	ipv6 := make([]byte, 16)
	ipv6[15] = 0x01 // ::1
	b := buildSegmentBytes(SegmentType9, 0x80, ipv6)

	seg, err := UnmarshalSRSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalSRSegment Type9: %v", err)
	}
	s := seg.(*SRSegment)
	if s.Segment != SegmentType9 {
		t.Errorf("Segment = %d, want %d", s.Segment, SegmentType9)
	}
}

// TestUnmarshalSRSegment_Type1_NoSID verifies SegmentType1 without FlagS set does not panic.
func TestUnmarshalSRSegment_Type1_NoSID(t *testing.T) {
	b := buildSegmentBytes(SegmentType1, 0x00 /* FlagS clear */, nil)
	seg, err := UnmarshalSRSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalSRSegment Type1 no SID: %v", err)
	}
	s := seg.(*SRSegment)
	if s.FlagS {
		t.Error("FlagS = true, want false")
	}
	if s.SID != nil {
		t.Error("SID should be nil when FlagS is clear")
	}
}

// TestUnmarshalSRSegment_Type3_NoSID verifies SegmentType3 without FlagS set does not panic.
func TestUnmarshalSRSegment_Type3_NoSID(t *testing.T) {
	b := buildSegmentBytes(SegmentType3, 0x00, nil)
	seg, err := UnmarshalSRSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalSRSegment Type3 no SID: %v", err)
	}
	s := seg.(*SRSegment)
	if s.Segment != SegmentType3 {
		t.Errorf("Segment = %d, want %d", s.Segment, SegmentType3)
	}
}

// TestUnmarshalSRSegment_InvalidType verifies type 0 (SegmentTypeInvalid) returns an error.
func TestUnmarshalSRSegment_InvalidType(t *testing.T) {
	b := buildSegmentBytes(SegmentTypeInvalid, 0x00, nil)
	_, err := UnmarshalSRSegment(b)
	if err == nil {
		t.Error("expected error for SegmentTypeInvalid, got nil")
	}
}

// TestUnmarshalSRType3Descriptor verifies parsing of a 5-byte Type3 descriptor.
func TestUnmarshalSRType3Descriptor(t *testing.T) {
	b := []byte{10, 0, 0, 1, 128} // IPv4 10.0.0.1, Algorithm 128
	d, err := UnmarshalSRType3Descriptor(b)
	if err != nil {
		t.Fatalf("UnmarshalSRType3Descriptor: %v", err)
	}
	desc := d.(*SRType3Descriptor)
	if desc.Algorithm != 128 {
		t.Errorf("Algorithm = %d, want 128", desc.Algorithm)
	}
	if desc.Len() != 5 {
		t.Errorf("Len() = %d, want 5", desc.Len())
	}
}

// TestUnmarshalSRType4Descriptor verifies parsing of a 17-byte Type4 descriptor.
func TestUnmarshalSRType4Descriptor(t *testing.T) {
	b := make([]byte, 17)
	b[16] = 64 // Algorithm 64
	d, err := UnmarshalSRType4Descriptor(b)
	if err != nil {
		t.Fatalf("UnmarshalSRType4Descriptor: %v", err)
	}
	desc := d.(*SRType4Descriptor)
	if desc.Algorithm != 64 {
		t.Errorf("Algorithm = %d, want 64", desc.Algorithm)
	}
	if desc.Len() != 17 {
		t.Errorf("Len() = %d, want 17", desc.Len())
	}
}

// TestUnmarshalSRType5Descriptor verifies parsing of an 8-byte Type5 descriptor.
func TestUnmarshalSRType5Descriptor(t *testing.T) {
	b := make([]byte, 8)
	b[0], b[1], b[2], b[3] = 192, 168, 1, 1
	binary.BigEndian.PutUint32(b[4:], 42)
	d, err := UnmarshalSRType5Descriptor(b)
	if err != nil {
		t.Fatalf("UnmarshalSRType5Descriptor: %v", err)
	}
	desc := d.(*SRType5Descriptor)
	if desc.LocalInterfaceID != 42 {
		t.Errorf("LocalInterfaceID = %d, want 42", desc.LocalInterfaceID)
	}
	if desc.Len() != 8 {
		t.Errorf("Len() = %d, want 8", desc.Len())
	}
}

// TestUnmarshalSRType6Descriptor verifies parsing of an 8-byte Type6 descriptor.
func TestUnmarshalSRType6Descriptor(t *testing.T) {
	b := []byte{10, 0, 0, 1, 10, 0, 0, 2}
	d, err := UnmarshalSRType6Descriptor(b)
	if err != nil {
		t.Fatalf("UnmarshalSRType6Descriptor: %v", err)
	}
	desc := d.(*SRType6Descriptor)
	if desc.LocalInterfaceIPv4[3] != 1 {
		t.Errorf("LocalInterfaceIPv4[3] = %d, want 1", desc.LocalInterfaceIPv4[3])
	}
	if desc.RemoteInterfaceIPv4[3] != 2 {
		t.Errorf("RemoteInterfaceIPv4[3] = %d, want 2", desc.RemoteInterfaceIPv4[3])
	}
	if desc.Len() != 8 {
		t.Errorf("Len() = %d, want 8", desc.Len())
	}
}

// TestUnmarshalSRType7Descriptor verifies parsing of a 40-byte Type7 descriptor.
func TestUnmarshalSRType7Descriptor(t *testing.T) {
	b := make([]byte, 40)
	b[15] = 1
	binary.BigEndian.PutUint32(b[16:20], 10)
	b[35] = 2
	binary.BigEndian.PutUint32(b[36:40], 20)
	d, err := UnmarshalSRType7Descriptor(b)
	if err != nil {
		t.Fatalf("UnmarshalSRType7Descriptor: %v", err)
	}
	desc := d.(*SRType7Descriptor)
	if desc.LocalInterfaceID != 10 {
		t.Errorf("LocalInterfaceID = %d, want 10", desc.LocalInterfaceID)
	}
	if desc.RemoteInterfaceID != 20 {
		t.Errorf("RemoteInterfaceID = %d, want 20", desc.RemoteInterfaceID)
	}
	if desc.Len() != 40 {
		t.Errorf("Len() = %d, want 40", desc.Len())
	}
}

// TestUnmarshalSRType8Descriptor verifies parsing of a 32-byte Type8 descriptor.
func TestUnmarshalSRType8Descriptor(t *testing.T) {
	b := make([]byte, 32)
	b[15] = 3
	b[31] = 4
	d, err := UnmarshalSRType8Descriptor(b)
	if err != nil {
		t.Fatalf("UnmarshalSRType8Descriptor: %v", err)
	}
	desc := d.(*SRType8Descriptor)
	if desc.LocalInterfaceIPv6[15] != 3 {
		t.Errorf("LocalInterfaceIPv6[15] = %d, want 3", desc.LocalInterfaceIPv6[15])
	}
	if desc.RemoteInterfaceIPv6[15] != 4 {
		t.Errorf("RemoteInterfaceIPv6[15] = %d, want 4", desc.RemoteInterfaceIPv6[15])
	}
	if desc.Len() != 32 {
		t.Errorf("Len() = %d, want 32", desc.Len())
	}
}

// TestUnmarshalSRType3Descriptor_BadLength verifies error on too-short input.
func TestUnmarshalSRType3Descriptor_BadLength(t *testing.T) {
	_, err := UnmarshalSRType3Descriptor([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for short Type3 descriptor, got nil")
	}
}

// TestUnmarshalSRSegment_Type2_WithSID verifies SegmentType2 parses an SRv6 SID.
func TestUnmarshalSRSegment_Type2_WithSID(t *testing.T) {
	ipv6 := make([]byte, 16)
	ipv6[0] = 0x20 // 2000::
	b := buildSegmentBytes(SegmentType2, 0x80, ipv6)

	seg, err := UnmarshalSRSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalSRSegment Type2: %v", err)
	}
	if seg.(*SRSegment).Segment != SegmentType2 {
		t.Errorf("Segment = %d, want %d", seg.(*SRSegment).Segment, SegmentType2)
	}
}

// TestUnmarshalSRSegment_MPLSTypes_WithSID verifies types 4-8 all parse an MPLS Label SID.
func TestUnmarshalSRSegment_MPLSTypes_WithSID(t *testing.T) {
	label := uint32(300) << 12
	sid := make([]byte, 4)
	binary.BigEndian.PutUint32(sid, label)

	for _, segType := range []SegmentType{SegmentType4, SegmentType5, SegmentType6, SegmentType7, SegmentType8} {
		b := buildSegmentBytes(segType, 0x80, sid)
		seg, err := UnmarshalSRSegment(b)
		if err != nil {
			t.Fatalf("UnmarshalSRSegment type %d: %v", segType, err)
		}
		if seg.(*SRSegment).Segment != segType {
			t.Errorf("type %d: Segment = %d, want %d", segType, seg.(*SRSegment).Segment, segType)
		}
	}
}

// TestUnmarshalSRSegment_SRv6Types_WithSID verifies types 10-11 parse an SRv6 SID.
func TestUnmarshalSRSegment_SRv6Types_WithSID(t *testing.T) {
	ipv6 := make([]byte, 16)
	ipv6[15] = 0x02

	for _, segType := range []SegmentType{SegmentType10, SegmentType11} {
		b := buildSegmentBytes(segType, 0x80, ipv6)
		seg, err := UnmarshalSRSegment(b)
		if err != nil {
			t.Fatalf("UnmarshalSRSegment type %d: %v", segType, err)
		}
		if seg.(*SRSegment).Segment != segType {
			t.Errorf("type %d: Segment = %d, want %d", segType, seg.(*SRSegment).Segment, segType)
		}
	}
}

// TestUnmarshalSRSegment_UnknownType verifies an unknown segment type returns an error.
func TestUnmarshalSRSegment_UnknownType(t *testing.T) {
	b := buildSegmentBytes(SegmentType(99), 0x00, nil)
	_, err := UnmarshalSRSegment(b)
	if err == nil {
		t.Error("expected error for unknown segment type 99, got nil")
	}
}

// TestUnmarshalSRSegment_Type1_WithDescriptor verifies FlagA triggers Type1 descriptor parsing.
func TestUnmarshalSRSegment_Type1_WithDescriptor(t *testing.T) {
	// FlagA=0x08, FlagS clear — header (4) + Type1 descriptor (1 byte algorithm).
	b := []byte{byte(SegmentType1), 0x00, 0x08, 0x00, 0x80} // algorithm = 128
	seg, err := UnmarshalSRSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalSRSegment Type1 with descriptor: %v", err)
	}
	s := seg.(*SRSegment)
	if s.SegmentDescriptor == nil {
		t.Fatal("SegmentDescriptor is nil, want non-nil")
	}
	if s.SegmentDescriptor.Len() != 1 {
		t.Errorf("descriptor Len() = %d, want 1", s.SegmentDescriptor.Len())
	}
}

// TestUnmarshalSRSegment_Type3_WithDescriptor verifies FlagA triggers Type3 descriptor parsing.
func TestUnmarshalSRSegment_Type3_WithDescriptor(t *testing.T) {
	// FlagS=0x80 + FlagA=0x08 — header(4) + MPLS SID(4) + Type3 descriptor(5).
	label := uint32(100) << 12
	sid := make([]byte, 4)
	binary.BigEndian.PutUint32(sid, label)
	desc := []byte{10, 0, 0, 1, 64} // IPv4 10.0.0.1, algo 64
	b := buildSegmentBytes(SegmentType3, 0x80|0x08, append(sid, desc...))

	seg, err := UnmarshalSRSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalSRSegment Type3 with descriptor: %v", err)
	}
	s := seg.(*SRSegment)
	if s.SegmentDescriptor == nil {
		t.Fatal("SegmentDescriptor is nil, want non-nil")
	}
	d := s.SegmentDescriptor.(*SRType3Descriptor)
	if d.Algorithm != 64 {
		t.Errorf("Algorithm = %d, want 64", d.Algorithm)
	}
}

// TestUnmarshalSRSegment_Type9_WithDescriptor verifies FlagA triggers Type4 descriptor parsing for Type9.
func TestUnmarshalSRSegment_Type9_WithDescriptor(t *testing.T) {
	// FlagS=0x80 + FlagA=0x08 — header(4) + SRv6 SID(16) + Type4 descriptor(17).
	ipv6SID := make([]byte, 16)
	ipv6SID[15] = 1
	desc := make([]byte, 17) // IPv6 node + algo 0
	desc[16] = 32            // algorithm 32
	b := buildSegmentBytes(SegmentType9, 0x80|0x08, append(ipv6SID, desc...))

	seg, err := UnmarshalSRSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalSRSegment Type9 with descriptor: %v", err)
	}
	s := seg.(*SRSegment)
	if s.SegmentDescriptor == nil {
		t.Fatal("SegmentDescriptor is nil, want non-nil")
	}
	d := s.SegmentDescriptor.(*SRType4Descriptor)
	if d.Algorithm != 32 {
		t.Errorf("Algorithm = %d, want 32", d.Algorithm)
	}
}

// TestUnmarshalSRSegment_FlagA_NoBytes verifies error when FlagA is set but no bytes remain.
func TestUnmarshalSRSegment_FlagA_NoBytes(t *testing.T) {
	// FlagA set but buffer is exactly 4 bytes (header only) — no descriptor bytes.
	b := []byte{byte(SegmentType1), 0x00, 0x08, 0x00}
	_, err := UnmarshalSRSegment(b)
	if err == nil {
		t.Error("expected error when FlagA set but no descriptor bytes, got nil")
	}
}

// TestUnmarshalSRType4Descriptor_BadLength verifies error on too-short input.
func TestUnmarshalSRType4Descriptor_BadLength(t *testing.T) {
	_, err := UnmarshalSRType4Descriptor(make([]byte, 10))
	if err == nil {
		t.Error("expected error for short Type4 descriptor, got nil")
	}
}

// TestUnmarshalSRType5Descriptor_BadLength verifies error on too-short input.
func TestUnmarshalSRType5Descriptor_BadLength(t *testing.T) {
	_, err := UnmarshalSRType5Descriptor(make([]byte, 4))
	if err == nil {
		t.Error("expected error for short Type5 descriptor, got nil")
	}
}

// TestUnmarshalSRType6Descriptor_BadLength verifies error on too-short input.
func TestUnmarshalSRType6Descriptor_BadLength(t *testing.T) {
	_, err := UnmarshalSRType6Descriptor(make([]byte, 4))
	if err == nil {
		t.Error("expected error for short Type6 descriptor, got nil")
	}
}

// TestUnmarshalSRType7Descriptor_BadLength verifies error on too-short input.
func TestUnmarshalSRType7Descriptor_BadLength(t *testing.T) {
	_, err := UnmarshalSRType7Descriptor(make([]byte, 20))
	if err == nil {
		t.Error("expected error for short Type7 descriptor, got nil")
	}
}

// TestUnmarshalSRType8Descriptor_BadLength verifies error on too-short input.
func TestUnmarshalSRType8Descriptor_BadLength(t *testing.T) {
	_, err := UnmarshalSRType8Descriptor(make([]byte, 16))
	if err == nil {
		t.Error("expected error for short Type8 descriptor, got nil")
	}
}

// TestUnmarshalSRSegment_TruncatedMPLSSID verifies error when FlagS is set but buffer
// is too short to hold the 4-byte MPLS SID.
func TestUnmarshalSRSegment_TruncatedMPLSSID(t *testing.T) {
	// Header only (4 bytes) with FlagS set — MPLS SID requires 4 more bytes.
	b := []byte{byte(SegmentType1), 0x00, 0x80, 0x00}
	_, err := UnmarshalSRSegment(b)
	if err == nil {
		t.Error("expected error for truncated MPLS SID, got nil")
	}
}

// TestUnmarshalSRSegment_TruncatedSRv6SID verifies error when FlagS is set but buffer
// is too short to hold the 16-byte SRv6 SID.
func TestUnmarshalSRSegment_TruncatedSRv6SID(t *testing.T) {
	// Header (4 bytes) + 4 bytes — SRv6 SID requires 16 bytes, so 20 total.
	b := append([]byte{byte(SegmentType9), 0x00, 0x80, 0x00}, make([]byte, 4)...)
	_, err := UnmarshalSRSegment(b)
	if err == nil {
		t.Error("expected error for truncated SRv6 SID, got nil")
	}
}
