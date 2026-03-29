package bgpls

import (
	"encoding/binary"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalBGPLSTLV
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalBGPLSTLV(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		wantN   int // number of TLVs expected on success
	}{
		{
			name:    "empty buffer returns empty slice",
			input:   []byte{},
			wantErr: false,
			wantN:   0,
		},
		{
			name:    "single zero-length TLV",
			input:   []byte{0x04, 0x00, 0x00, 0x00}, // type=1024 len=0
			wantErr: false,
			wantN:   1,
		},
		{
			name: "two TLVs back to back",
			input: []byte{
				0x04, 0x00, 0x00, 0x02, 0xAB, 0xCD, // type=1024 len=2 value=0xABCD
				0x04, 0x03, 0x00, 0x01, 0xFF, // type=1027 len=1 value=0xFF
			},
			wantErr: false,
			wantN:   2,
		},
		{
			name:    "truncated: only 1 byte — cannot read Type",
			input:   []byte{0x04},
			wantErr: true,
		},
		{
			name:    "truncated: 3 bytes — cannot read Length",
			input:   []byte{0x04, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "declared length exceeds available bytes",
			input:   []byte{0x04, 0x00, 0x00, 0x10, 0x01, 0x02}, // len=16 but only 2 bytes follow
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBGPLSTLV(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBGPLSTLV() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(got) != tt.wantN {
				t.Errorf("len(tlvs) = %d, want %d", len(got), tt.wantN)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalIGPFlags
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalIGPFlags(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		wantD   bool
		wantN   bool
		wantL   bool
		wantP   bool
	}{
		{
			name:    "empty buffer returns error",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:  "all flags clear",
			input: []byte{0x00},
		},
		{
			name:  "all flags set: D=bit0 N=bit1 L=bit2 P=bit3",
			input: []byte{0x0F},
			wantD: true, wantN: true, wantL: true, wantP: true,
		},
		{
			name:  "only D flag set",
			input: []byte{0x01},
			wantD: true,
		},
		{
			name:  "extra bytes ignored",
			input: []byte{0x01, 0xFF},
			wantD: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalIGPFlags(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalIGPFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.DFlag != tt.wantD {
				t.Errorf("DFlag = %v, want %v", got.DFlag, tt.wantD)
			}
			if got.NFlag != tt.wantN {
				t.Errorf("NFlag = %v, want %v", got.NFlag, tt.wantN)
			}
			if got.LFlag != tt.wantL {
				t.Errorf("LFlag = %v, want %v", got.LFlag, tt.wantL)
			}
			if got.PFlag != tt.wantP {
				t.Errorf("PFlag = %v, want %v", got.PFlag, tt.wantP)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalNodeAttrFlags
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalNodeAttrFlags(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		wantO   bool
		wantT   bool
		wantE   bool
		wantB   bool
		wantR   bool
		wantV   bool
	}{
		{name: "empty input errors", input: []byte{}, wantErr: true},
		{name: "all clear", input: []byte{0x00}},
		{
			name:  "all set",
			input: []byte{0xFC}, // bits 7-2: O T E B R V
			wantO: true, wantT: true, wantE: true, wantB: true, wantR: true, wantV: true,
		},
		{name: "only O bit", input: []byte{0x80}, wantO: true},
		{name: "only R bit", input: []byte{0x08}, wantR: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalNodeAttrFlags(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalNodeAttrFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.OFlag != tt.wantO || got.TFlag != tt.wantT || got.EFlag != tt.wantE ||
				got.BFlag != tt.wantB || got.RFlag != tt.wantR || got.VFlag != tt.wantV {
				t.Errorf("flags mismatch: got O=%v T=%v E=%v B=%v R=%v V=%v",
					got.OFlag, got.TFlag, got.EFlag, got.BFlag, got.RFlag, got.VFlag)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// NLRI getter guards — len < minimum returns zero/nil without panic
// ─────────────────────────────────────────────────────────────────────────────

func TestGetAdminGroup_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1088, Length: 2, Value: []byte{0x01, 0x02}}}}
	if got := nlri.GetAdminGroup(); got != 0 {
		t.Errorf("GetAdminGroup() with short value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1088, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x2A}}}}
	if got := nlri2.GetAdminGroup(); got != 42 {
		t.Errorf("GetAdminGroup() = %d, want 42", got)
	}
}

func TestGetTEDefaultMetric_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1092, Length: 1, Value: []byte{0xFF}}}}
	if got := nlri.GetTEDefaultMetric(); got != 0 {
		t.Errorf("GetTEDefaultMetric() with short value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1092, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x64}}}}
	if got := nlri2.GetTEDefaultMetric(); got != 100 {
		t.Errorf("GetTEDefaultMetric() = %d, want 100", got)
	}
}

func TestGetPrefixMetric_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1155, Length: 2, Value: []byte{0x00, 0x01}}}}
	if got := nlri.GetPrefixMetric(); got != 0 {
		t.Errorf("GetPrefixMetric() with short value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1155, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x05}}}}
	if got := nlri2.GetPrefixMetric(); got != 5 {
		t.Errorf("GetPrefixMetric() = %d, want 5", got)
	}
}

func TestGetUnidirLinkDelay_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1114, Length: 3, Value: []byte{0x00, 0x00, 0x01}}}}
	if got := nlri.GetUnidirLinkDelay(); got != 0 {
		t.Errorf("GetUnidirLinkDelay() with short value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1114, Length: 4, Value: []byte{0x00, 0x00, 0x03, 0xE8}}}}
	if got := nlri2.GetUnidirLinkDelay(); got != 1000 {
		t.Errorf("GetUnidirLinkDelay() = %d, want 1000", got)
	}
}

func TestGetUnidirDelayVariation_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1116, Length: 2, Value: []byte{0x00, 0x01}}}}
	if got := nlri.GetUnidirDelayVariation(); got != 0 {
		t.Errorf("GetUnidirDelayVariation() with short value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1116, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x0A}}}}
	if got := nlri2.GetUnidirDelayVariation(); got != 10 {
		t.Errorf("GetUnidirDelayVariation() = %d, want 10", got)
	}
}

func TestGetUnidirLinkLoss_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1117, Length: 1, Value: []byte{0x01}}}}
	if got := nlri.GetUnidirLinkLoss(); got != 0 {
		t.Errorf("GetUnidirLinkLoss() with short value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1117, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x07}}}}
	if got := nlri2.GetUnidirLinkLoss(); got != 7 {
		t.Errorf("GetUnidirLinkLoss() = %d, want 7", got)
	}
}

func TestGetUnidirResidualBandwidth_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1118, Length: 2, Value: []byte{0x00, 0x01}}}}
	if got := nlri.GetUnidirResidualBandwidth(); got != 0 {
		t.Errorf("GetUnidirResidualBandwidth() with short value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1118, Length: 4, Value: []byte{0x00, 0x00, 0x01, 0x00}}}}
	if got := nlri2.GetUnidirResidualBandwidth(); got != 256 {
		t.Errorf("GetUnidirResidualBandwidth() = %d, want 256", got)
	}
}

func TestGetUnidirAvailableBandwidth_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1119, Length: 1, Value: []byte{0xFF}}}}
	if got := nlri.GetUnidirAvailableBandwidth(); got != 0 {
		t.Errorf("GetUnidirAvailableBandwidth() with short value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1119, Length: 4, Value: []byte{0x00, 0x00, 0x02, 0x00}}}}
	if got := nlri2.GetUnidirAvailableBandwidth(); got != 512 {
		t.Errorf("GetUnidirAvailableBandwidth() = %d, want 512", got)
	}
}

func TestGetUnidirUtilizedBandwidth_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1120, Length: 3, Value: []byte{0x00, 0x00, 0x01}}}}
	if got := nlri.GetUnidirUtilizedBandwidth(); got != 0 {
		t.Errorf("GetUnidirUtilizedBandwidth() with short value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1120, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x08}}}}
	if got := nlri2.GetUnidirUtilizedBandwidth(); got != 8 {
		t.Errorf("GetUnidirUtilizedBandwidth() = %d, want 8", got)
	}
}

func TestGetLinkProtectionType_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1093, Length: 1, Value: []byte{0xFF}}}}
	if got := nlri.GetLinkProtectionType(); got != 0 {
		t.Errorf("GetLinkProtectionType() with short value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1093, Length: 2, Value: []byte{0x00, 0x04}}}}
	if got := nlri2.GetLinkProtectionType(); got != 4 {
		t.Errorf("GetLinkProtectionType() = %d, want 4", got)
	}
}

func TestGetLinkMPLSProtocolMask_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1094, Length: 0, Value: []byte{}}}}
	if got := nlri.GetLinkMPLSProtocolMask(); got != 0 {
		t.Errorf("GetLinkMPLSProtocolMask() with empty value = %d, want 0", got)
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1094, Length: 1, Value: []byte{0xC0}}}}
	if got := nlri2.GetLinkMPLSProtocolMask(); got != 0xC0 {
		t.Errorf("GetLinkMPLSProtocolMask() = 0x%X, want 0xC0", got)
	}
}

func TestGetUnidirLinkDelayMinMax_Guards(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1115, Length: 4, Value: []byte{0x00, 0x00, 0x01, 0x00}}}}
	if got := nlri.GetUnidirLinkDelayMinMax(); got != nil {
		t.Errorf("GetUnidirLinkDelayMinMax() with short value = %v, want nil", got)
	}
	val := make([]byte, 8)
	binary.BigEndian.PutUint32(val[0:4], 100)
	binary.BigEndian.PutUint32(val[4:8], 200)
	nlri2 := &NLRI{LS: []TLV{{Type: 1115, Length: 8, Value: val}}}
	got := nlri2.GetUnidirLinkDelayMinMax()
	if len(got) != 2 || got[0] != 100 || got[1] != 200 {
		t.Errorf("GetUnidirLinkDelayMinMax() = %v, want [100 200]", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetSRLG — non-multiple-of-4 length returns empty, valid multiple parses
// ─────────────────────────────────────────────────────────────────────────────

func TestGetSRLG(t *testing.T) {
	tests := []struct {
		name  string
		tlv   TLV
		wantN int
	}{
		{
			name:  "no TLV 1096 — returns nil",
			tlv:   TLV{Type: 9999, Length: 4, Value: []byte{0, 0, 0, 1}},
			wantN: -1, // nil sentinel
		},
		{
			name:  "length not multiple of 4 — returns empty",
			tlv:   TLV{Type: 1096, Length: 5, Value: []byte{0, 0, 0, 1, 0xFF}},
			wantN: 0,
		},
		{
			name: "two SRLG values",
			tlv: TLV{Type: 1096, Length: 8, Value: func() []byte {
				b := make([]byte, 8)
				binary.BigEndian.PutUint32(b[0:4], 111)
				binary.BigEndian.PutUint32(b[4:8], 222)
				return b
			}()},
			wantN: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{tt.tlv}}
			got := nlri.GetSRLG()
			if tt.wantN == -1 {
				if got != nil {
					t.Errorf("GetSRLG() = %v, want nil", got)
				}
				return
			}
			if len(got) != tt.wantN {
				t.Errorf("GetSRLG() len = %d, want %d; got %v", len(got), tt.wantN, got)
			}
			if tt.wantN == 2 && (got[0] != 111 || got[1] != 222) {
				t.Errorf("GetSRLG() values = %v, want [111 222]", got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetNodeFlags
// ─────────────────────────────────────────────────────────────────────────────

func TestGetNodeFlags(t *testing.T) {
	tests := []struct {
		name    string
		tlvs    []TLV
		wantErr bool
		wantO   bool
		wantR   bool
	}{
		{
			name:    "TLV 1024 absent — error",
			tlvs:    []TLV{},
			wantErr: true,
		},
		{
			name:  "TLV 1024 with O and R flags set",
			tlvs:  []TLV{{Type: 1024, Length: 1, Value: []byte{0x80 | 0x08}}},
			wantO: true, wantR: true,
		},
		{
			name:    "TLV 1024 with empty value — error from unmarshal",
			tlvs:    []TLV{{Type: 1024, Length: 0, Value: []byte{}}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: tt.tlvs}
			got, err := nlri.GetNodeFlags()
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetNodeFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.OFlag != tt.wantO {
				t.Errorf("OFlag = %v, want %v", got.OFlag, tt.wantO)
			}
			if got.RFlag != tt.wantR {
				t.Errorf("RFlag = %v, want %v", got.RFlag, tt.wantR)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetIGPMetric — variable-length 1–3 bytes, invalid lengths return 0
// ─────────────────────────────────────────────────────────────────────────────

func TestGetIGPMetric(t *testing.T) {
	tests := []struct {
		name string
		tlv  TLV
		want uint32
	}{
		{
			name: "1-byte metric = 10",
			tlv:  TLV{Type: 1095, Length: 1, Value: []byte{0x0A}},
			want: 10,
		},
		{
			name: "2-byte metric = 1000",
			tlv:  TLV{Type: 1095, Length: 2, Value: []byte{0x03, 0xE8}},
			want: 1000,
		},
		{
			name: "3-byte metric = 65536",
			tlv:  TLV{Type: 1095, Length: 3, Value: []byte{0x01, 0x00, 0x00}},
			want: 65536,
		},
		{
			name: "length 0 — returns 0",
			tlv:  TLV{Type: 1095, Length: 0, Value: []byte{}},
			want: 0,
		},
		{
			name: "length 5 — returns 0",
			tlv:  TLV{Type: 1095, Length: 5, Value: []byte{1, 2, 3, 4, 5}},
			want: 0,
		},
		{
			name: "TLV absent — returns 0",
			tlv:  TLV{Type: 9999, Length: 4, Value: []byte{0, 0, 0, 1}},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{tt.tlv}}
			if got := nlri.GetIGPMetric(); got != tt.want {
				t.Errorf("GetIGPMetric() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalSRBindingSID
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalSRBindingSID(t *testing.T) {
	makeMPLS := func(flags byte, bsidLabel, psidLabel uint32) []byte {
		b := make([]byte, 12)
		b[0] = flags
		// b[1..3] reserved
		binary.BigEndian.PutUint32(b[4:8], bsidLabel<<12)
		binary.BigEndian.PutUint32(b[8:12], psidLabel<<12)
		return b
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		checkFn func(*testing.T, *SRBindingSID)
	}{
		{
			name:    "empty buffer — invalid length error",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:  "MPLS, FlagB set, PSID present (12 bytes)",
			input: makeMPLS(0x40, 100, 200),
			checkFn: func(t *testing.T, b *SRBindingSID) {
				if !b.FlagB {
					t.Error("FlagB should be set")
				}
				if b.FlagD {
					t.Error("FlagD should be clear for MPLS")
				}
			},
		},
		{
			name:  "MPLS, FlagU set — PSID field skipped",
			input: makeMPLS(0x20, 100, 0),
			checkFn: func(t *testing.T, b *SRBindingSID) {
				if !b.FlagU {
					t.Error("FlagU should be set")
				}
				if b.PSID != nil {
					t.Error("PSID should be nil when FlagU is set")
				}
			},
		},
		{
			name:  "MPLS, FlagD clear FlagU clear (12 bytes)",
			input: makeMPLS(0x00, 16, 32),
			checkFn: func(t *testing.T, b *SRBindingSID) {
				if b.FlagD || b.FlagB || b.FlagU {
					t.Error("no flags should be set")
				}
			},
		},
		{
			name: "SRv6, FlagD set, 36 bytes",
			input: func() []byte {
				b := make([]byte, 36)
				b[0] = 0x80 // FlagD
				// BSID = 16 bytes at offset 4, PSID = 16 bytes at offset 20
				b[4] = 0x20
				b[19] = 0x01 // BSID ends in ::01
				b[20] = 0x20
				b[35] = 0x02 // PSID ends in ::02
				return b
			}(),
			checkFn: func(t *testing.T, b *SRBindingSID) {
				if !b.FlagD {
					t.Error("FlagD should be set for SRv6")
				}
			},
		},
		{
			name:    "truncated: 6 bytes — not enough even for MPLS BSID",
			input:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRBindingSID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalSRBindingSID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.checkFn != nil {
				tt.checkFn(t, got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalSRCandidatePathState
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalSRCandidatePathState(t *testing.T) {
	validInput := func(priority uint8, flags1, flags2 byte, pref uint32) []byte {
		b := make([]byte, 8)
		b[0] = priority
		// b[1] reserved
		b[2] = flags1
		b[3] = flags2
		binary.BigEndian.PutUint32(b[4:8], pref)
		return b
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		checkFn func(*testing.T, *SRCandidatePathState)
	}{
		{
			name:    "wrong length (7 bytes)",
			input:   make([]byte, 7),
			wantErr: true,
		},
		{
			name:    "wrong length (9 bytes)",
			input:   make([]byte, 9),
			wantErr: true,
		},
		{
			name:  "priority=5 FlagA FlagV pref=100",
			input: validInput(5, 0x40|0x08, 0x00, 100),
			checkFn: func(t *testing.T, s *SRCandidatePathState) {
				if s.Priority != 5 {
					t.Errorf("Priority = %d, want 5", s.Priority)
				}
				if !s.FlagA {
					t.Error("FlagA should be set")
				}
				if !s.FlagV {
					t.Error("FlagV should be set")
				}
				if s.Preference != 100 {
					t.Errorf("Preference = %d, want 100", s.Preference)
				}
			},
		},
		{
			name:  "FlagI and FlagT in second flags byte",
			input: validInput(0, 0x00, 0x80|0x40, 0),
			checkFn: func(t *testing.T, s *SRCandidatePathState) {
				if !s.FlagI {
					t.Error("FlagI should be set")
				}
				if !s.FlagT {
					t.Error("FlagT should be set")
				}
			},
		},
		{
			name:  "all flags clear, pref=0",
			input: validInput(0, 0x00, 0x00, 0),
			checkFn: func(t *testing.T, s *SRCandidatePathState) {
				if s.FlagS || s.FlagA || s.FlagB || s.FlagE || s.FlagV || s.FlagO || s.FlagD || s.FlagC {
					t.Error("no flags should be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRCandidatePathState(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalSRCandidatePathState() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.checkFn != nil {
				tt.checkFn(t, got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalSRAffinityConstraint
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalSRAffinityConstraint(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		checkFn func(*testing.T, *SRAffinityConstraint)
	}{
		{
			name:    "too short (3 bytes)",
			input:   []byte{0x01, 0x01, 0x01},
			wantErr: true,
		},
		{
			name:  "all sizes zero — no EAG fields",
			input: []byte{0x00, 0x00, 0x00, 0x00},
			checkFn: func(t *testing.T, s *SRAffinityConstraint) {
				if s.ExclAnyEAG != 0 || s.InclAnyEAG != 0 || s.InclAllEAG != 0 {
					t.Error("all EAG values should be zero")
				}
			},
		},
		{
			name: "all three EAG fields present",
			input: func() []byte {
				b := make([]byte, 16) // 4 header + 3×4 EAG
				b[0] = 1              // ExclAnySize
				b[1] = 1              // InclAnySize
				b[2] = 1              // InclAllSize
				// b[3] reserved
				binary.BigEndian.PutUint32(b[4:8], 0xDEAD0001)
				binary.BigEndian.PutUint32(b[8:12], 0xBEEF0002)
				binary.BigEndian.PutUint32(b[12:16], 0xCAFE0003)
				return b
			}(),
			checkFn: func(t *testing.T, s *SRAffinityConstraint) {
				if s.ExclAnyEAG != 0xDEAD0001 {
					t.Errorf("ExclAnyEAG = 0x%X, want 0xDEAD0001", s.ExclAnyEAG)
				}
				if s.InclAnyEAG != 0xBEEF0002 {
					t.Errorf("InclAnyEAG = 0x%X, want 0xBEEF0002", s.InclAnyEAG)
				}
				if s.InclAllEAG != 0xCAFE0003 {
					t.Errorf("InclAllEAG = 0x%X, want 0xCAFE0003", s.InclAllEAG)
				}
			},
		},
		{
			name: "ExclAnySize set but not enough bytes — error",
			input: []byte{
				0x01,       // ExclAnySize = 1
				0x00, 0x00, // InclAnySize, InclAllSize = 0
				0x00, // reserved
				// no EAG bytes follow
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRAffinityConstraint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalSRAffinityConstraint() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.checkFn != nil {
				tt.checkFn(t, got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalSRSRLGConstraint
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalSRSRLGConstraint(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		wantIDs []uint32
	}{
		{
			name:    "empty buffer — too short",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "3 bytes — too short",
			input:   []byte{0x00, 0x00, 0x01},
			wantErr: true,
		},
		{
			name:    "5 bytes — not multiple of 4",
			input:   []byte{0x00, 0x00, 0x00, 0x01, 0xFF},
			wantErr: true,
		},
		{
			name:    "one SRLG value",
			input:   []byte{0x00, 0x00, 0x00, 0x2A},
			wantIDs: []uint32{42},
		},
		{
			name: "three SRLG values",
			input: func() []byte {
				b := make([]byte, 12)
				binary.BigEndian.PutUint32(b[0:4], 10)
				binary.BigEndian.PutUint32(b[4:8], 20)
				binary.BigEndian.PutUint32(b[8:12], 30)
				return b
			}(),
			wantIDs: []uint32{10, 20, 30},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRSRLGConstraint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalSRSRLGConstraint() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got.SRLG) != len(tt.wantIDs) {
				t.Fatalf("len(SRLG) = %d, want %d", len(got.SRLG), len(tt.wantIDs))
			}
			for i, id := range tt.wantIDs {
				if got.SRLG[i] != id {
					t.Errorf("SRLG[%d] = %d, want %d", i, got.SRLG[i], id)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalSRBandwidthConstraint
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalSRBandwidthConstraint(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		wantBW  uint32
	}{
		{name: "too short", input: []byte{0x00, 0x00, 0x01}, wantErr: true},
		{name: "too long", input: []byte{0x00, 0x00, 0x00, 0x64, 0xFF}, wantErr: true},
		{name: "bandwidth = 100", input: []byte{0x00, 0x00, 0x00, 0x64}, wantBW: 100},
		{name: "bandwidth = 0", input: []byte{0x00, 0x00, 0x00, 0x00}, wantBW: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRBandwidthConstraint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalSRBandwidthConstraint() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.Bandwidth != tt.wantBW {
				t.Errorf("Bandwidth = %d, want %d", got.Bandwidth, tt.wantBW)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalSRDisjointGroupConstraint
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalSRDisjointGroupConstraint(t *testing.T) {
	makeInput := func(reqFlags, statFlags byte, id uint32) []byte {
		b := make([]byte, 8)
		b[0] = reqFlags
		b[1] = statFlags
		// b[2..3] reserved
		binary.BigEndian.PutUint32(b[4:8], id)
		return b
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		checkFn func(*testing.T, *SRDisjointGroupConstraint)
	}{
		{name: "too short (7 bytes)", input: make([]byte, 7), wantErr: true},
		{name: "too long (9 bytes)", input: make([]byte, 9), wantErr: true},
		{
			name:  "request flags S and N, group ID 99",
			input: makeInput(0x80|0x40, 0x00, 99),
			checkFn: func(t *testing.T, d *SRDisjointGroupConstraint) {
				if !d.RequestFlagS {
					t.Error("RequestFlagS should be set")
				}
				if !d.RequestFlagN {
					t.Error("RequestFlagN should be set")
				}
				if d.DisjointGroupID != 99 {
					t.Errorf("DisjointGroupID = %d, want 99", d.DisjointGroupID)
				}
			},
		},
		{
			name:  "status flags S L and X",
			input: makeInput(0x00, 0x80|0x20|0x04, 0),
			checkFn: func(t *testing.T, d *SRDisjointGroupConstraint) {
				if !d.StatusFlagS {
					t.Error("StatusFlagS should be set")
				}
				if !d.StatusFlagL {
					t.Error("StatusFlagL should be set")
				}
				if !d.StatusFlagX {
					t.Error("StatusFlagX should be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRDisjointGroupConstraint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalSRDisjointGroupConstraint() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.checkFn != nil {
				tt.checkFn(t, got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalSRCandidatePathConstraints
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalSRCandidatePathConstraints(t *testing.T) {
	makeBase := func(flags byte, mtid uint16, algo uint8) []byte {
		b := make([]byte, 8)
		b[0] = flags
		// b[1] reserved
		binary.BigEndian.PutUint16(b[2:4], mtid)
		b[4] = algo
		// b[5..7] reserved
		return b
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		checkFn func(*testing.T, *SRCandidatePathConstraints)
	}{
		{name: "too short (7 bytes)", input: make([]byte, 7), wantErr: true},
		{
			name:  "FlagD set, MTID=10, Algo=128",
			input: makeBase(0x80, 10, 128),
			checkFn: func(t *testing.T, s *SRCandidatePathConstraints) {
				if !s.FlagD {
					t.Error("FlagD should be set")
				}
				if s.MTID != 10 {
					t.Errorf("MTID = %d, want 10", s.MTID)
				}
				if s.Algo != 128 {
					t.Errorf("Algo = %d, want 128", s.Algo)
				}
			},
		},
		{
			name:  "all flags clear",
			input: makeBase(0x00, 0, 0),
			checkFn: func(t *testing.T, s *SRCandidatePathConstraints) {
				if s.FlagD || s.FlagP || s.FlagU || s.FlagA || s.FlagT {
					t.Error("no flags should be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRCandidatePathConstraints(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalSRCandidatePathConstraints() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.checkFn != nil {
				tt.checkFn(t, got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalFlexAlgoDefinition — additional error cases
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalFlexAlgoDefinition_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		checkFn func(*testing.T, *FlexAlgoDefinition)
	}{
		{
			name:    "too short (3 bytes)",
			input:   []byte{0x80, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:  "exactly 4 bytes — no sub-TLVs",
			input: []byte{128, 0, 0, 200},
			checkFn: func(t *testing.T, f *FlexAlgoDefinition) {
				if f.FlexAlgorithm != 128 {
					t.Errorf("FlexAlgorithm = %d, want 128", f.FlexAlgorithm)
				}
				if f.Priority != 200 {
					t.Errorf("Priority = %d, want 200", f.Priority)
				}
				if f.SubTLV != nil {
					t.Error("SubTLV should be nil with no sub-TLV bytes")
				}
			},
		},
		{
			// type 1040 = 0x0410, length = 8, two ExcludeAny entries
			name: "sub-TLV type 1040 ExcludeAny two entries",
			input: []byte{
				128, 0, 0, 200, // base: FlexAlgo, MetricType, CalcType, Priority
				0x04, 0x10, 0x00, 0x08, // type=1040, length=8
				0x00, 0x00, 0x00, 0x01, // entry 1
				0x00, 0x00, 0x00, 0x02, // entry 2
			},
			checkFn: func(t *testing.T, f *FlexAlgoDefinition) {
				if f.SubTLV == nil {
					t.Fatal("SubTLV should not be nil")
				}
				if len(f.SubTLV.ExcludeAny) != 2 {
					t.Errorf("ExcludeAny len = %d, want 2", len(f.SubTLV.ExcludeAny))
				}
			},
		},
		{
			// type 1041 = 0x0411, length = 4, one IncludeAny entry
			name: "sub-TLV type 1041 IncludeAny one entry",
			input: []byte{
				128, 0, 0, 200,
				0x04, 0x11, 0x00, 0x04, // type=1041, length=4
				0x00, 0x00, 0x00, 0x0A, // entry = 10
			},
			checkFn: func(t *testing.T, f *FlexAlgoDefinition) {
				if f.SubTLV == nil || len(f.SubTLV.IncludeAny) != 1 || f.SubTLV.IncludeAny[0] != 10 {
					t.Errorf("IncludeAny = %v, want [10]", f.SubTLV.IncludeAny)
				}
			},
		},
		{
			// type 1042 = 0x0412, length = 4, one IncludeAll entry
			name: "sub-TLV type 1042 IncludeAll one entry",
			input: []byte{
				128, 0, 0, 200,
				0x04, 0x12, 0x00, 0x04, // type=1042, length=4
				0x00, 0x00, 0x00, 0x14, // entry = 20
			},
			checkFn: func(t *testing.T, f *FlexAlgoDefinition) {
				if f.SubTLV == nil || len(f.SubTLV.IncludeAll) != 1 || f.SubTLV.IncludeAll[0] != 20 {
					t.Errorf("IncludeAll = %v, want [20]", f.SubTLV.IncludeAll)
				}
			},
		},
		{
			// type 1043 = 0x0413, length = 1, MFlag=true
			name: "sub-TLV type 1043 Flags MFlag=true",
			input: []byte{
				128, 0, 0, 200,
				0x04, 0x13, 0x00, 0x01, // type=1043, length=1
				0x80, // MFlag=1
			},
			checkFn: func(t *testing.T, f *FlexAlgoDefinition) {
				if f.SubTLV == nil || f.SubTLV.Flags == nil || !f.SubTLV.Flags.MFLag {
					t.Error("Flags.MFLag should be true")
				}
			},
		},
		{
			// type 1043 = 0x0413, length = 0 — too short for flags byte
			name:    "sub-TLV type 1043 Flags zero length",
			wantErr: true,
			input: []byte{
				128, 0, 0, 200,
				0x04, 0x13, 0x00, 0x00, // type=1043, length=0 (invalid)
			},
		},
		{
			// type 1045 = 0x0415, length = 4, one ExcludeSRLG entry
			name: "sub-TLV type 1045 ExcludeSRLG one entry",
			input: []byte{
				128, 0, 0, 200,
				0x04, 0x15, 0x00, 0x04, // type=1045, length=4
				0x00, 0x00, 0x00, 0x1E, // entry = 30
			},
			checkFn: func(t *testing.T, f *FlexAlgoDefinition) {
				if f.SubTLV == nil || len(f.SubTLV.ExcludeSRLG) != 1 || f.SubTLV.ExcludeSRLG[0] != 30 {
					t.Errorf("ExcludeSRLG = %v, want [30]", f.SubTLV.ExcludeSRLG)
				}
			},
		},
		{
			// Unknown type — logged as warning, not an error
			name: "sub-TLV unknown type 9999",
			input: []byte{
				128, 0, 0, 200,
				0x27, 0x0F, 0x00, 0x04, // type=9999(unknown), length=4
				0x00, 0x00, 0x00, 0x00,
			},
			checkFn: func(t *testing.T, f *FlexAlgoDefinition) {
				// No error expected; SubTLV is allocated but fields remain zero-value
				if f.SubTLV == nil {
					t.Error("SubTLV should be allocated even for unknown types")
				}
			},
		},
		{
			// type 1040 with length=3 (not multiple of 4) — getFADSubTLVValue error
			name:    "sub-TLV type 1040 length not multiple of 4",
			wantErr: true,
			input: []byte{
				128, 0, 0, 200,
				0x04, 0x10, 0x00, 0x03, // type=1040, length=3 (invalid)
				0xAA, 0xBB, 0xCC,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalFlexAlgoDefinition(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalFlexAlgoDefinition() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.checkFn != nil {
				tt.checkFn(t, got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// NLRI simple string/value getters
// ─────────────────────────────────────────────────────────────────────────────

func TestGetNodeName(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1026, Length: 4, Value: []byte("rtr1")}}}
	if got := nlri.GetNodeName(); got != "rtr1" {
		t.Errorf("GetNodeName() = %q, want %q", got, "rtr1")
	}
	nlri2 := &NLRI{LS: []TLV{}}
	if got := nlri2.GetNodeName(); got != "" {
		t.Errorf("GetNodeName() absent = %q, want empty", got)
	}
}

func TestGetLinkName(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1098, Length: 5, Value: []byte("eth0/")}}}
	if got := nlri.GetLinkName(); got != "eth0/" {
		t.Errorf("GetLinkName() = %q, want %q", got, "eth0/")
	}
}

func TestGetSRAlgorithm(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1035, Length: 3, Value: []byte{0, 128, 129}}}}
	got := nlri.GetSRAlgorithm()
	if len(got) != 3 || got[0] != 0 || got[1] != 128 || got[2] != 129 {
		t.Errorf("GetSRAlgorithm() = %v, want [0 128 129]", got)
	}
	nlriEmpty := &NLRI{LS: []TLV{}}
	if got2 := nlriEmpty.GetSRAlgorithm(); len(got2) != 0 {
		t.Errorf("GetSRAlgorithm() absent = %v, want []", got2)
	}
}

func TestGetLocalIPv4RouterID(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1028, Length: 4, Value: []byte{10, 0, 0, 1}}}}
	if got := nlri.GetLocalIPv4RouterID(); got != "10.0.0.1" {
		t.Errorf("GetLocalIPv4RouterID() = %q, want 10.0.0.1", got)
	}
	if got := (&NLRI{}).GetLocalIPv4RouterID(); got != "" {
		t.Errorf("GetLocalIPv4RouterID() absent = %q, want empty", got)
	}
	if got := (&NLRI{LS: []TLV{{Type: 1028, Length: 2, Value: []byte{10, 0}}}}).GetLocalIPv4RouterID(); got != "" {
		t.Errorf("GetLocalIPv4RouterID() short value = %q, want empty", got)
	}
}

func TestGetRemoteIPv4RouterID(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1030, Length: 4, Value: []byte{192, 168, 1, 1}}}}
	if got := nlri.GetRemoteIPv4RouterID(); got != "192.168.1.1" {
		t.Errorf("GetRemoteIPv4RouterID() = %q, want 192.168.1.1", got)
	}
	if got := (&NLRI{LS: []TLV{{Type: 1030, Length: 1, Value: []byte{10}}}}).GetRemoteIPv4RouterID(); got != "" {
		t.Errorf("GetRemoteIPv4RouterID() short value = %q, want empty", got)
	}
}

func TestGetLocalIPv6RouterID(t *testing.T) {
	addr := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	nlri := &NLRI{LS: []TLV{{Type: 1029, Length: 16, Value: addr}}}
	if got := nlri.GetLocalIPv6RouterID(); got != "2001:db8::1" {
		t.Errorf("GetLocalIPv6RouterID() = %q, want 2001:db8::1", got)
	}
	if got := (&NLRI{LS: []TLV{{Type: 1029, Length: 4, Value: []byte{10, 0, 0, 1}}}}).GetLocalIPv6RouterID(); got != "" {
		t.Errorf("GetLocalIPv6RouterID() short value = %q, want empty", got)
	}
}

func TestGetRemoteIPv6RouterID(t *testing.T) {
	addr := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	nlri := &NLRI{LS: []TLV{{Type: 1031, Length: 16, Value: addr}}}
	if got := nlri.GetRemoteIPv6RouterID(); got != "2001:db8::2" {
		t.Errorf("GetRemoteIPv6RouterID() = %q, want 2001:db8::2", got)
	}
	if got := (&NLRI{LS: []TLV{{Type: 1031, Length: 8, Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0}}}}).GetRemoteIPv6RouterID(); got != "" {
		t.Errorf("GetRemoteIPv6RouterID() short value = %q, want empty", got)
	}
}

func TestGetISISAreaID(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1027, Length: 6, Value: []byte{0x49, 0x00, 0x01, 0x0A, 0x00, 0x00}}}}
	if got := nlri.GetISISAreaID(); got == "" {
		t.Error("GetISISAreaID() returned empty, expected non-empty")
	}
	if got := (&NLRI{}).GetISISAreaID(); got != "" {
		t.Errorf("GetISISAreaID() absent = %q, want empty", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalSRCandidatePathName (always succeeds, just wraps string)
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalSRCandidatePathName(t *testing.T) {
	got, err := UnmarshalSRCandidatePathName([]byte("my-policy"))
	if err != nil {
		t.Fatalf("UnmarshalSRCandidatePathName() error = %v", err)
	}
	if got.SymbolicName != "my-policy" {
		t.Errorf("SymbolicName = %q, want my-policy", got.SymbolicName)
	}
	// empty bytes — still succeeds with empty string
	got2, err := UnmarshalSRCandidatePathName([]byte{})
	if err != nil {
		t.Fatalf("UnmarshalSRCandidatePathName() empty error = %v", err)
	}
	if got2.SymbolicName != "" {
		t.Errorf("SymbolicName = %q, want empty", got2.SymbolicName)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetLinkID
// ─────────────────────────────────────────────────────────────────────────────

func TestGetLinkID(t *testing.T) {
	valid := make([]byte, 8)
	binary.BigEndian.PutUint32(valid[0:4], 11)
	binary.BigEndian.PutUint32(valid[4:8], 22)

	tests := []struct {
		name    string
		tlvs    []TLV
		wantErr bool
		wantL   uint32
		wantR   uint32
	}{
		{
			name:    "TLV 258 absent",
			tlvs:    []TLV{},
			wantErr: true,
		},
		{
			name:    "TLV 258 too short",
			tlvs:    []TLV{{Type: 258, Length: 4, Value: []byte{0, 0, 0, 1}}},
			wantErr: true,
		},
		{
			name:  "valid 8-byte TLV",
			tlvs:  []TLV{{Type: 258, Length: 8, Value: valid}},
			wantL: 11, wantR: 22,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: tt.tlvs}
			got, err := nlri.GetLinkID()
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetLinkID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got[0] != tt.wantL || got[1] != tt.wantR {
				t.Errorf("GetLinkID() = [%d %d], want [%d %d]", got[0], got[1], tt.wantL, tt.wantR)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalBGPLSNLRI round-trip
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalBGPLSNLRI_Malformed(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{name: "empty is error", input: nil, wantErr: true},
		{name: "only 1 byte", input: []byte{0x04}, wantErr: true},
		{name: "header only no value length overflow", input: []byte{0x04, 0x00, 0x00, 0x05, 0x01}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalBGPLSNLRI(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBGPLSNLRI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
