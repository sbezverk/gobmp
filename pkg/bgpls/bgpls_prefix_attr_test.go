package bgpls

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalFlexAlgoPrefixMetric
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalFlexAlgoPrefixMetric(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		wantErr    bool
		wantAlgo   uint8
		wantMetric uint32
	}{
		{
			name:    "too short (7 bytes)",
			input:   make([]byte, 7),
			wantErr: true,
		},
		{
			name:       "algo=128, metric=1000",
			input:      []byte{128, 0, 0, 0, 0x00, 0x00, 0x03, 0xE8},
			wantAlgo:   128,
			wantMetric: 1000,
		},
		{
			name:       "algo=0, metric=0",
			input:      []byte{0, 0, 0, 0, 0, 0, 0, 0},
			wantAlgo:   0,
			wantMetric: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalFlexAlgoPrefixMetric(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalFlexAlgoPrefixMetric() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.FlexAlgorithm != tt.wantAlgo {
				t.Errorf("FlexAlgorithm = %d, want %d", got.FlexAlgorithm, tt.wantAlgo)
			}
			if got.Metric != tt.wantMetric {
				t.Errorf("Metric = %d, want %d", got.Metric, tt.wantMetric)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalPrefixAttrFlags — dispatch to protocol-specific unmarshalers
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalPrefixAttrFlags(t *testing.T) {
	tests := []struct {
		name     string
		proto    base.ProtoID
		input    []byte
		wantErr  bool
		wantByte byte
	}{
		{
			name:    "empty input returns error",
			proto:   base.ISISL1,
			input:   []byte{},
			wantErr: true,
		},
		{
			name:     "ISIS L1 X+R flags",
			proto:    base.ISISL1,
			input:    []byte{0xC0}, // X=bit7, R=bit6
			wantByte: 0xC0,
		},
		{
			name:     "ISIS L2",
			proto:    base.ISISL2,
			input:    []byte{0x20}, // N=bit5
			wantByte: 0x20,
		},
		{
			name:     "OSPFv2 A flag",
			proto:    base.OSPFv2,
			input:    []byte{0x80},
			wantByte: 0x80,
		},
		{
			name:     "OSPFv3 NU flag",
			proto:    base.OSPFv3,
			input:    []byte{0x01},
			wantByte: 0x01,
		},
		{
			name:     "Unknown proto",
			proto:    base.BGP,
			input:    []byte{0xAB},
			wantByte: 0xAB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalPrefixAttrFlags(tt.input, tt.proto)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalPrefixAttrFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.GetPrefixAttrFlagsByte() != tt.wantByte {
				t.Errorf("GetPrefixAttrFlagsByte() = 0x%X, want 0x%X", got.GetPrefixAttrFlagsByte(), tt.wantByte)
			}
		})
	}
}

func TestUnmarshalPrefixAttrFlags_EmptyInput(t *testing.T) {
	// B4: empty input must return an error, not panic with an index out-of-range.
	for _, proto := range []base.ProtoID{base.ISISL1, base.ISISL2, base.OSPFv2, base.OSPFv3, base.BGP} {
		if _, err := UnmarshalPrefixAttrFlags([]byte{}, proto); err == nil {
			t.Errorf("proto %v: expected error for empty input, got nil", proto)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual prefix attr flag unmarshalers
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalISISFlags(t *testing.T) {
	// empty → error
	if _, err := UnmarshalISISFlags([]byte{}); err == nil {
		t.Error("expected error for empty input")
	}
	// X+R+N set: 0xE0
	got, err := UnmarshalISISFlags([]byte{0xE0})
	if err != nil {
		t.Fatalf("UnmarshalISISFlags() error = %v", err)
	}
	if !got.XFlag || !got.RFlag || !got.NFlag {
		t.Errorf("all flags should be set, got X=%v R=%v N=%v", got.XFlag, got.RFlag, got.NFlag)
	}
	if got.GetPrefixAttrFlagsByte() != 0xE0 {
		t.Errorf("GetPrefixAttrFlagsByte() = 0x%X, want 0xE0", got.GetPrefixAttrFlagsByte())
	}
	// all clear
	got2, _ := UnmarshalISISFlags([]byte{0x00})
	if got2.XFlag || got2.RFlag || got2.NFlag {
		t.Error("no flags should be set")
	}
}

func TestUnmarshalOSPFFlags(t *testing.T) {
	if _, err := UnmarshalOSPFFlags([]byte{}); err == nil {
		t.Error("expected error for empty input")
	}
	got, err := UnmarshalOSPFFlags([]byte{0x80})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !got.AFlag || got.NFlag {
		t.Errorf("AFlag should be set, NFlag clear; got A=%v N=%v", got.AFlag, got.NFlag)
	}
	if got.GetPrefixAttrFlagsByte() != 0x80 {
		t.Errorf("GetPrefixAttrFlagsByte() = 0x%X, want 0x80", got.GetPrefixAttrFlagsByte())
	}
	// N flag (bit 6 = 0x40)
	got2, _ := UnmarshalOSPFFlags([]byte{0x40})
	if !got2.NFlag {
		t.Error("NFlag should be set")
	}
}

func TestUnmarshalOSPFv3Flags(t *testing.T) {
	if _, err := UnmarshalOSPFv3Flags([]byte{}); err == nil {
		t.Error("expected error for empty input")
	}
	// N=0x20, DN=0x10, P=0x08, LA=0x02, NU=0x01
	got, err := UnmarshalOSPFv3Flags([]byte{0x3B})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !got.NFlag || !got.DNFlag || !got.PFlag || !got.LAFlag || !got.NUFlag {
		t.Errorf("all flags should be set: N=%v DN=%v P=%v LA=%v NU=%v",
			got.NFlag, got.DNFlag, got.PFlag, got.LAFlag, got.NUFlag)
	}
	if got.GetPrefixAttrFlagsByte() != 0x3B {
		t.Errorf("GetPrefixAttrFlagsByte() = 0x%X, want 0x3B", got.GetPrefixAttrFlagsByte())
	}
}

func TestUnmarshalUnknownProtoFlags(t *testing.T) {
	if _, err := UnmarshalUnknownProtoFlags([]byte{}); err == nil {
		t.Error("expected error for empty input")
	}
	got, err := UnmarshalUnknownProtoFlags([]byte{0xAB})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if got.Flags != 0xAB || got.GetPrefixAttrFlagsByte() != 0xAB {
		t.Errorf("flags = 0x%X, want 0xAB", got.Flags)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Range TLV Flags
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalRangeTLVFlags(t *testing.T) {
	tests := []struct {
		name     string
		b        byte
		proto    base.ProtoID
		wantByte byte
	}{
		{name: "ISIS FFlag", b: 0x80, proto: base.ISISL1, wantByte: 0x80},
		{name: "ISIS all flags", b: 0xF8, proto: base.ISISL2, wantByte: 0xF8},
		{name: "OSPF IAFlag", b: 0x80, proto: base.OSPFv2, wantByte: 0x80},
		{name: "OSPF no flags", b: 0x00, proto: base.OSPFv3, wantByte: 0x00},
		{name: "Unknown proto", b: 0x55, proto: base.BGP, wantByte: 0x55},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalRangeTLVFlags(tt.b, tt.proto)
			if err != nil {
				t.Fatalf("UnmarshalRangeTLVFlags() error = %v", err)
			}
			if got.GetRangeFlagsByte() != tt.wantByte {
				t.Errorf("GetRangeFlagsByte() = 0x%X, want 0x%X", got.GetRangeFlagsByte(), tt.wantByte)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON round-trip tests for constraint types
// ─────────────────────────────────────────────────────────────────────────────

func TestSRAffinityConstraint_JSON(t *testing.T) {
	orig := &SRAffinityConstraint{
		ExclAnySize: 1,
		InclAnySize: 2,
		InclAllSize: 3,
		ExclAnyEAG:  0xDEAD0001,
		InclAnyEAG:  0xBEEF0002,
		InclAllEAG:  0xCAFE0003,
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRAffinityConstraint{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.ExclAnySize != orig.ExclAnySize || got.InclAnySize != orig.InclAnySize || got.InclAllSize != orig.InclAllSize {
		t.Errorf("size fields mismatch: got %+v, want %+v", got, orig)
	}
	if got.ExclAnyEAG != orig.ExclAnyEAG || got.InclAnyEAG != orig.InclAnyEAG || got.InclAllEAG != orig.InclAllEAG {
		t.Errorf("EAG fields mismatch: got %+v, want %+v", got, orig)
	}
}

func TestSRSRLGConstraint_JSON(t *testing.T) {
	orig := &SRSRLGConstraint{SRLG: []uint32{10, 20, 30}}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRSRLGConstraint{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if len(got.SRLG) != len(orig.SRLG) {
		t.Fatalf("SRLG len mismatch: got %d, want %d", len(got.SRLG), len(orig.SRLG))
	}
	for i := range orig.SRLG {
		if got.SRLG[i] != orig.SRLG[i] {
			t.Errorf("SRLG[%d] = %d, want %d", i, got.SRLG[i], orig.SRLG[i])
		}
	}
}

func TestSRBandwidthConstraint_JSON(t *testing.T) {
	orig := &SRBandwidthConstraint{Bandwidth: 500}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRBandwidthConstraint{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Bandwidth != orig.Bandwidth {
		t.Errorf("Bandwidth = %d, want %d", got.Bandwidth, orig.Bandwidth)
	}
}

func TestSRDisjointGroupConstraint_JSON(t *testing.T) {
	orig := &SRDisjointGroupConstraint{
		RequestFlagS:    true,
		RequestFlagN:    false,
		RequestFlagL:    true,
		RequestFlagF:    false,
		RequestFlagI:    true,
		StatusFlagS:     true,
		StatusFlagN:     false,
		StatusFlagL:     true,
		StatusFlagF:     false,
		StatusFlagI:     true,
		StatusFlagX:     false,
		DisjointGroupID: 42,
	}
	b, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &SRDisjointGroupConstraint{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.RequestFlagS != orig.RequestFlagS || got.RequestFlagN != orig.RequestFlagN ||
		got.RequestFlagL != orig.RequestFlagL || got.RequestFlagF != orig.RequestFlagF ||
		got.RequestFlagI != orig.RequestFlagI {
		t.Errorf("request flags mismatch: got %+v, want %+v", got, orig)
	}
	if got.StatusFlagS != orig.StatusFlagS || got.StatusFlagN != orig.StatusFlagN ||
		got.StatusFlagL != orig.StatusFlagL || got.StatusFlagF != orig.StatusFlagF ||
		got.StatusFlagI != orig.StatusFlagI || got.StatusFlagX != orig.StatusFlagX {
		t.Errorf("status flags mismatch: got %+v, want %+v", got, orig)
	}
	if got.DisjointGroupID != orig.DisjointGroupID {
		t.Errorf("DisjointGroupID = %d, want %d", got.DisjointGroupID, orig.DisjointGroupID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PrefixAttrTLVs MarshalJSON / UnmarshalJSON
// ─────────────────────────────────────────────────────────────────────────────

func TestPrefixAttrTLVs_MarshalJSON_Empty(t *testing.T) {
	p := &PrefixAttrTLVs{}
	b, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	// Empty PrefixAttrTLVs returns nil bytes (not error)
	if b != nil {
		// This is also acceptable — verify it's valid JSON or nil
		// Some implementations return nil for empty structs
		if len(b) > 0 {
			var dummy interface{}
			if jsonErr := json.Unmarshal(b, &dummy); jsonErr != nil {
				t.Errorf("non-nil result is not valid JSON: %v", jsonErr)
			}
		}
	}
}

func TestPrefixAttrTLVs_MarshalJSON_WithISISFlags(t *testing.T) {
	p := &PrefixAttrTLVs{
		Flags:          &ISISFlags{XFlag: true, RFlag: false, NFlag: true},
		SourceRouterID: "10.0.0.1",
	}
	b, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	if len(b) == 0 {
		t.Fatal("expected non-empty JSON")
	}
	// Unmarshal back
	got := &PrefixAttrTLVs{}
	if err := got.UnmarshalJSON(b); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.SourceRouterID != "10.0.0.1" {
		t.Errorf("SourceRouterID = %q, want 10.0.0.1", got.SourceRouterID)
	}
}

func TestPrefixAttrTLVs_MarshalJSON_WithOSPFFlags(t *testing.T) {
	p := &PrefixAttrTLVs{
		Flags:          &OSPFFlags{AFlag: true, NFlag: false},
		SourceRouterID: "192.168.1.1",
	}
	b, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	got := &PrefixAttrTLVs{}
	if err := got.UnmarshalJSON(b); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.SourceRouterID != "192.168.1.1" {
		t.Errorf("SourceRouterID = %q, want 192.168.1.1", got.SourceRouterID)
	}
}

func TestPrefixAttrTLVs_MarshalJSON_WithUnknownFlags(t *testing.T) {
	p := &PrefixAttrTLVs{
		Flags:          &UnknownProtoFlags{Flags: 0xAB},
		SourceRouterID: "172.16.0.1",
	}
	b, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	_ = b // valid JSON bytes
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalSRCandidatePathConstraintsSubTLV
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalSRCandidatePathConstraintsSubTLV(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		wantN   int // number of sub-TLVs expected
	}{
		{
			name:    "too short (3 bytes)",
			input:   make([]byte, 3),
			wantErr: true,
		},
		{
			name: "single bandwidth constraint sub-TLV",
			input: func() []byte {
				// type=SRBandwidthConstraintType, len=4, value=100
				b := make([]byte, 8)
				// SRBandwidthConstraintType needs to be the right constant
				// SRBandwidthConstraintType = 1210 = 0x04BA
				b[0] = 0x04
				b[1] = 0xBA // type = 0x04BA = 1210
				b[2] = 0x00
				b[3] = 0x04 // length = 4
				b[4] = 0x00
				b[5] = 0x00
				b[6] = 0x00
				b[7] = 0x64 // value = 100
				return b
			}(),
			wantN: 1,
		},
		{
			name: "truncated sub-TLV value",
			input: func() []byte {
				b := make([]byte, 7) // header says length=4 but only 3 bytes follow
				b[0] = 0x04
				b[1] = 0xBA // type = 1210
				b[2] = 0x00
				b[3] = 0x04 // claims length=4
				// only 3 bytes of value
				return b
			}(),
			wantErr: true,
		},
		{
			// SRAffinityConstraintType = 1208 = 0x04B8, all-zero (sizes=0, no EAG words)
			name: "affinity constraint zero sizes",
			input: []byte{
				0x04, 0xB8, 0x00, 0x04, // type=1208, length=4
				0x00, 0x00, 0x00, 0x00, // ExclAnySize=0, InclAnySize=0, InclAllSize=0, reserved
			},
			wantN: 1,
		},
		{
			// SRSRLGConstraintType = 1209 = 0x04B9, one SRLG entry
			name: "SRLG constraint one entry",
			input: []byte{
				0x04, 0xB9, 0x00, 0x04, // type=1209, length=4
				0x00, 0x00, 0x00, 0xAA, // SRLG=0xAA
			},
			wantN: 1,
		},
		{
			// SRDisjointGroupConstraintType = 1211 = 0x04BB, 8 bytes
			name: "disjoint group constraint",
			input: []byte{
				0x04, 0xBB, 0x00, 0x08, // type=1211, length=8
				0x80,       // RequestFlagS=1
				0x80,       // StatusFlagS=1
				0x00, 0x00, // reserved
				0x00, 0x00, 0x00, 0x2A, // DisjointGroupID=42
			},
			wantN: 1,
		},
		{
			// Unknown type — silently ignored, no sub-TLV added to map
			name: "unknown sub-TLV type ignored",
			input: []byte{
				0x27, 0x0F, 0x00, 0x04, // type=9999(unknown), length=4
				0x00, 0x00, 0x00, 0x00,
			},
			wantN: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRCandidatePathConstraintsSubTLV(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalSRCandidatePathConstraintsSubTLV() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.wantN >= 0 && len(got) != tt.wantN {
				t.Errorf("len(result) = %d, want %d", len(got), tt.wantN)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetPrefixAttrTLVs — drives multiple NLRI getters at once
// ─────────────────────────────────────────────────────────────────────────────

func TestGetPrefixAttrTLVs_Absent(t *testing.T) {
	// Empty NLRI — GetPrefixAttrTLVs returns error when nothing is present
	_, err := (&NLRI{}).GetPrefixAttrTLVs(base.ISISL1)
	if err == nil {
		t.Error("GetPrefixAttrTLVs() empty NLRI: expected error, got nil")
	}
}

func TestGetPrefixAttrTLVs_SourceRouterID(t *testing.T) {
	// TLV 1171 with a 4-byte IPv4 address
	nlri := &NLRI{LS: []TLV{{Type: 1171, Length: 4, Value: []byte{10, 0, 0, 1}}}}
	result, err := nlri.GetPrefixAttrTLVs(base.ISISL1)
	if err != nil {
		t.Fatalf("GetPrefixAttrTLVs() error = %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil when SourceRouterID is set")
	}
	if result.SourceRouterID != "10.0.0.1" {
		t.Errorf("SourceRouterID = %q, want 10.0.0.1", result.SourceRouterID)
	}
}

func TestGetPrefixAttrTLVs_PrefixAttrFlags(t *testing.T) {
	// TLV 1170 with ISIS flags X set (0x80)
	nlri := &NLRI{LS: []TLV{{Type: 1170, Length: 1, Value: []byte{0x80}}}}
	result, err := nlri.GetPrefixAttrTLVs(base.ISISL1)
	if err != nil {
		t.Fatalf("GetPrefixAttrTLVs() error = %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil when Flags are set")
	}
	if result.Flags == nil {
		t.Fatal("Flags should be populated")
	}
	if result.Flags.GetPrefixAttrFlagsByte() != 0x80 {
		t.Errorf("Flags byte = 0x%X, want 0x80", result.Flags.GetPrefixAttrFlagsByte())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ISISRangeFlags / OSPFRangeFlags round-trips
// ─────────────────────────────────────────────────────────────────────────────

func TestISISRangeFlags_GetRangeFlagsByte(t *testing.T) {
	f := &ISISRangeFlags{FFlag: true, MFlag: true, SFlag: false, DFlag: true, AFlag: false}
	b := f.GetRangeFlagsByte()
	// F=0x80, M=0x40, D=0x10
	if b != 0xD0 {
		t.Errorf("GetRangeFlagsByte() = 0x%X, want 0xD0", b)
	}
}

func TestOSPFRangeFlags_GetRangeFlagsByte(t *testing.T) {
	f1 := &OSPFRangeFlags{IAFlag: true}
	if f1.GetRangeFlagsByte() != 0x80 {
		t.Errorf("IAFlag=true: got 0x%X, want 0x80", f1.GetRangeFlagsByte())
	}
	f2 := &OSPFRangeFlags{IAFlag: false}
	if f2.GetRangeFlagsByte() != 0x00 {
		t.Errorf("IAFlag=false: got 0x%X, want 0x00", f2.GetRangeFlagsByte())
	}
}
