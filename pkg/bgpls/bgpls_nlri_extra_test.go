package bgpls

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// ─────────────────────────────────────────────────────────────────────────────
// Deprecated bandwidth getters (always return 0/nil)
// ─────────────────────────────────────────────────────────────────────────────

func TestDeprecatedBandwidthGetters(t *testing.T) {
	nlri := &NLRI{}
	if v := nlri.GetMaxLinkBandwidth(); v != 0 {
		t.Errorf("GetMaxLinkBandwidth() = %d, want 0", v)
	}
	if v := nlri.GetMaxReservableLinkBandwidth(); v != 0 {
		t.Errorf("GetMaxReservableLinkBandwidth() = %d, want 0", v)
	}
	if v := nlri.GetUnreservedLinkBandwidth(); v != nil {
		t.Errorf("GetUnreservedLinkBandwidth() = %v, want nil", v)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Kbps bandwidth getters
// ─────────────────────────────────────────────────────────────────────────────

func float32Bytes(f float32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, math.Float32bits(f))
	return b
}

func TestGetMaxLinkBandwidthKbps(t *testing.T) {
	// Absent → 0
	if got := (&NLRI{}).GetMaxLinkBandwidthKbps(); got != 0 {
		t.Errorf("absent → %d, want 0", got)
	}
	// Short value (< 4 bytes) → 0, not a panic
	nlriShort := &NLRI{LS: []TLV{{Type: 1089, Length: 3, Value: []byte{0x01, 0x02, 0x03}}}}
	if got := nlriShort.GetMaxLinkBandwidthKbps(); got != 0 {
		t.Errorf("short value → %d, want 0", got)
	}
	// Present: 125000 bytes/s = 125000*8/1000 kbps = 1000 kbps
	val := float32Bytes(125000)
	nlri := &NLRI{LS: []TLV{{Type: 1089, Length: 4, Value: val}}}
	if got := nlri.GetMaxLinkBandwidthKbps(); got != 1000 {
		t.Errorf("GetMaxLinkBandwidthKbps() = %d, want 1000", got)
	}
}

func TestGetMaxReservableLinkBandwidthKbps(t *testing.T) {
	if got := (&NLRI{}).GetMaxReservableLinkBandwidthKbps(); got != 0 {
		t.Errorf("absent → %d, want 0", got)
	}
	// Short value (< 4 bytes) → 0, not a panic
	nlriShort := &NLRI{LS: []TLV{{Type: 1090, Length: 2, Value: []byte{0x01, 0x02}}}}
	if got := nlriShort.GetMaxReservableLinkBandwidthKbps(); got != 0 {
		t.Errorf("short value → %d, want 0", got)
	}
	val := float32Bytes(62500)
	nlri := &NLRI{LS: []TLV{{Type: 1090, Length: 4, Value: val}}}
	if got := nlri.GetMaxReservableLinkBandwidthKbps(); got != 500 {
		t.Errorf("GetMaxReservableLinkBandwidthKbps() = %d, want 500", got)
	}
}

func TestGetUnreservedLinkBandwidthKbps(t *testing.T) {
	// Absent → nil
	if got := (&NLRI{}).GetUnreservedLinkBandwidthKbps(); got != nil {
		t.Errorf("absent → %v, want nil", got)
	}
	// Invalid length → returns default 8-element slice of 0
	shortVal := make([]byte, 8)
	nlri := &NLRI{LS: []TLV{{Type: 1091, Length: 8, Value: shortVal}}}
	got := nlri.GetUnreservedLinkBandwidthKbps()
	if len(got) != 8 {
		t.Errorf("invalid len: got slice of len %d, want 8", len(got))
	}
	// Valid: 32 bytes (8 x float32)
	val := make([]byte, 32)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(val[i*4:i*4+4], math.Float32bits(125000)) // 1000 kbps each
	}
	nlri2 := &NLRI{LS: []TLV{{Type: 1091, Length: 32, Value: val}}}
	got2 := nlri2.GetUnreservedLinkBandwidthKbps()
	if len(got2) != 8 {
		t.Fatalf("len(result) = %d, want 8", len(got2))
	}
	for i, v := range got2 {
		if v != 1000 {
			t.Errorf("result[%d] = %d, want 1000", i, v)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Prefix getters (bgp-ls-prefix.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestGetPrefixIGPFlags(t *testing.T) {
	// Absent → error
	_, err := (&NLRI{}).GetPrefixIGPFlags()
	if err == nil {
		t.Error("GetPrefixIGPFlags() absent: expected error, got nil")
	}
	// Present: D flag set
	nlri := &NLRI{LS: []TLV{{Type: 1152, Length: 1, Value: []byte{0x01}}}}
	got, err := nlri.GetPrefixIGPFlags()
	if err != nil {
		t.Fatalf("GetPrefixIGPFlags() error = %v", err)
	}
	if !got.DFlag {
		t.Error("GetPrefixIGPFlags() DFlag should be set")
	}
}

func TestGetPrefixIGPRouteTag(t *testing.T) {
	// Absent → nil
	if got := (&NLRI{}).GetPrefixIGPRouteTag(); got != nil {
		t.Errorf("absent → %v, want nil", got)
	}
	// Two tags
	val := make([]byte, 8)
	binary.BigEndian.PutUint32(val[0:4], 100)
	binary.BigEndian.PutUint32(val[4:8], 200)
	nlri := &NLRI{LS: []TLV{{Type: 1153, Length: 8, Value: val}}}
	got := nlri.GetPrefixIGPRouteTag()
	if len(got) != 2 || got[0] != 100 || got[1] != 200 {
		t.Errorf("GetPrefixIGPRouteTag() = %v, want [100 200]", got)
	}
	// Test non-multiple-of-4 value length
	nlriOdd := &NLRI{LS: []TLV{{Type: 1153, Value: []byte{0, 0, 0, 1, 0xFF, 0xFF}}}}
	tagsOdd := nlriOdd.GetPrefixIGPRouteTag()
	if len(tagsOdd) != 1 || tagsOdd[0] != 1 {
		t.Errorf("GetPrefixIGPRouteTag() non-multiple-of-4 = %v, want [1]", tagsOdd)
	}
}

func TestGetPrefixIGPExtRouteTag(t *testing.T) {
	// Absent → nil
	if got := (&NLRI{}).GetPrefixIGPExtRouteTag(); got != nil {
		t.Errorf("absent → %v, want nil", got)
	}
	// One 64-bit tag
	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, 0xDEADBEEFCAFE0001)
	nlri := &NLRI{LS: []TLV{{Type: 1154, Length: 8, Value: val}}}
	got := nlri.GetPrefixIGPExtRouteTag()
	if len(got) != 1 || got[0] != 0xDEADBEEFCAFE0001 {
		t.Errorf("GetPrefixIGPExtRouteTag() = %v", got)
	}
	// Test non-multiple-of-8 value length
	nlriOdd := &NLRI{LS: []TLV{{Type: 1154, Value: []byte{0, 0, 0, 0, 0, 0, 0, 1, 0xFF, 0xFF}}}}
	tagsOdd := nlriOdd.GetPrefixIGPExtRouteTag()
	if len(tagsOdd) != 1 || tagsOdd[0] != 1 {
		t.Errorf("GetPrefixIGPExtRouteTag() non-multiple-of-8 = %v, want [1]", tagsOdd)
	}
}

func TestGetPrefixOSPFForwardAddr(t *testing.T) {
	// Absent → empty
	if got := (&NLRI{}).GetPrefixOSPFForwardAddr(); got != "" {
		t.Errorf("absent → %q, want empty", got)
	}
	// IPv4 (length 4)
	nlri := &NLRI{LS: []TLV{{Type: 1156, Length: 4, Value: []byte{10, 1, 2, 3}}}}
	if got := nlri.GetPrefixOSPFForwardAddr(); got != "10.1.2.3" {
		t.Errorf("GetPrefixOSPFForwardAddr() = %q, want 10.1.2.3", got)
	}
	// IPv6 (length 16)
	ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}
	nlri2 := &NLRI{LS: []TLV{{Type: 1156, Length: 16, Value: ipv6}}}
	if got := nlri2.GetPrefixOSPFForwardAddr(); got != "2001:db8::5" {
		t.Errorf("GetPrefixOSPFForwardAddr() IPv6 = %q, want 2001:db8::5", got)
	}
	// Test invalid length (not 4 or 16)
	nlriInvalid := &NLRI{LS: []TLV{{Type: 1156, Value: []byte{1, 2, 3, 4, 5}}}}
	if got := nlriInvalid.GetPrefixOSPFForwardAddr(); got != "" {
		t.Errorf("GetPrefixOSPFForwardAddr() invalid length = %q, want empty", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// NLRI getters — "absent" path coverage for all remaining 0% functions
// ─────────────────────────────────────────────────────────────────────────────

func TestGetMTID_Absent(t *testing.T) {
	if got := (&NLRI{}).GetMTID(); got != nil {
		t.Errorf("GetMTID() absent = %v, want nil", got)
	}
}

func TestGetNodeMSD_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetNodeMSD()
	if err == nil {
		t.Error("GetNodeMSD() absent: expected error")
	}
}

func TestGetLinkMSD_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetLinkMSD()
	if err == nil {
		t.Error("GetLinkMSD() absent: expected error")
	}
}

func TestGetNodeSRCapabilities_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetNodeSRCapabilities(base.ISISL1)
	if err == nil {
		t.Error("GetNodeSRCapabilities() absent: expected error")
	}
}

func TestGetNodeSRLocalBlock_Absent(t *testing.T) {
	if got := (&NLRI{}).GetNodeSRLocalBlock(); got != nil {
		t.Errorf("GetNodeSRLocalBlock() absent = %v, want nil", got)
	}
}

func TestGetFlexAlgoDefinition_Absent(t *testing.T) {
	got, err := (&NLRI{}).GetFlexAlgoDefinition()
	if err != nil {
		t.Fatalf("GetFlexAlgoDefinition() absent error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("GetFlexAlgoDefinition() absent len = %d, want 0", len(got))
	}
}

func TestGetFlexAlgoPrefixMetric_Absent(t *testing.T) {
	got, err := (&NLRI{}).GetFlexAlgoPrefixMetric()
	if err != nil {
		t.Fatalf("GetFlexAlgoPrefixMetric() absent error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("GetFlexAlgoPrefixMetric() absent len = %d, want 0", len(got))
	}
}

func TestGetLSPrefixSID_Absent(t *testing.T) {
	got, err := (&NLRI{}).GetLSPrefixSID(base.ISISL1)
	if err != nil {
		t.Fatalf("GetLSPrefixSID() absent error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("GetLSPrefixSID() absent len = %d, want 0", len(got))
	}
}

func TestGetLSRangeTLV_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetLSRangeTLV(base.ISISL1)
	if err == nil {
		t.Error("GetLSRangeTLV() absent: expected error")
	}
}

func TestGetLSSRv6Locator_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetLSSRv6Locator()
	if err == nil {
		t.Error("GetLSSRv6Locator() absent: expected error")
	}
}

func TestGetLSPrefixAttrFlags_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetLSPrefixAttrFlags(base.ISISL1)
	if err == nil {
		t.Error("GetLSPrefixAttrFlags() absent: expected error")
	}
}

func TestGetLSSRv6ENDXSID_Absent(t *testing.T) {
	got, err := (&NLRI{}).GetLSSRv6ENDXSID()
	if err != nil {
		t.Fatalf("GetLSSRv6ENDXSID() absent error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("GetLSSRv6ENDXSID() absent len = %d, want 0", len(got))
	}
}

func TestGetNodeSRv6CapabilitiesTLV_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetNodeSRv6CapabilitiesTLV()
	if err == nil {
		t.Error("GetNodeSRv6CapabilitiesTLV() absent: expected error")
	}
}

func TestGetPeerNodeSID_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetPeerNodeSID()
	if err == nil {
		t.Error("GetPeerNodeSID() absent: expected error")
	}
}

func TestGetPeerAdjSID_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetPeerAdjSID()
	if err == nil {
		t.Error("GetPeerAdjSID() absent: expected error")
	}
}

func TestGetPeerSetSID_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetPeerSetSID()
	if err == nil {
		t.Error("GetPeerSetSID() absent: expected error")
	}
}

func TestGetSRv6EndpointBehavior_Absent(t *testing.T) {
	if got := (&NLRI{}).GetSRv6EndpointBehavior(); got != nil {
		t.Errorf("GetSRv6EndpointBehavior() absent = %v, want nil", got)
	}
}

func TestGetSRv6BGPPeerNodeSID_Absent(t *testing.T) {
	if got := (&NLRI{}).GetSRv6BGPPeerNodeSID(); got != nil {
		t.Errorf("GetSRv6BGPPeerNodeSID() absent = %v, want nil", got)
	}
}

func TestGetSRv6SIDStructure_Absent(t *testing.T) {
	if got := (&NLRI{}).GetSRv6SIDStructure(); got != nil {
		t.Errorf("GetSRv6SIDStructure() absent = %v, want nil", got)
	}
}

func TestGetAppSpecLinkAttr_Absent(t *testing.T) {
	got, err := (&NLRI{}).GetAppSpecLinkAttr()
	if err != nil {
		t.Fatalf("GetAppSpecLinkAttr() absent error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("GetAppSpecLinkAttr() absent len = %d, want 0", len(got))
	}
}

func TestGetSRAdjacencySID_Absent(t *testing.T) {
	got, err := (&NLRI{}).GetSRAdjacencySID(base.ISISL1)
	if err != nil {
		t.Fatalf("GetSRAdjacencySID() absent error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("GetSRAdjacencySID() absent len = %d, want 0", len(got))
	}
}

// NLRI getters wrapping SR policy unmarshalers — absent path
func TestGetSRBindingSID_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetSRBindingSID()
	if err == nil {
		t.Error("GetSRBindingSID() absent: expected error")
	}
}

func TestGetSRCandidatePathState_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetSRCandidatePathState()
	if err == nil {
		t.Error("GetSRCandidatePathState() absent: expected error")
	}
}

func TestGetSRCandidatePathName_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetSRCandidatePathName()
	if err == nil {
		t.Error("GetSRCandidatePathName() absent: expected error")
	}
}

func TestGetSRCandidatePathConstraints_Absent(t *testing.T) {
	_, err := (&NLRI{}).GetSRCandidatePathConstraints()
	if err == nil {
		t.Error("GetSRCandidatePathConstraints() absent: expected error")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// NLRI getters — "present" path hitting the Unmarshal delegate
// ─────────────────────────────────────────────────────────────────────────────

func TestGetSRBindingSID_Present(t *testing.T) {
	val := make([]byte, 12)
	val[0] = 0x40 // FlagB set
	nlri := &NLRI{LS: []TLV{{Type: BindingSIDType, Length: 12, Value: val}}}
	got, err := nlri.GetSRBindingSID()
	if err != nil {
		t.Fatalf("GetSRBindingSID() error = %v", err)
	}
	if !got.FlagB {
		t.Error("FlagB should be set")
	}
}

func TestGetSRCandidatePathState_Present(t *testing.T) {
	val := make([]byte, 8)
	val[0] = 7 // priority
	binary.BigEndian.PutUint32(val[4:8], 42)
	nlri := &NLRI{LS: []TLV{{Type: SRCandidatePathStateType, Length: 8, Value: val}}}
	got, err := nlri.GetSRCandidatePathState()
	if err != nil {
		t.Fatalf("GetSRCandidatePathState() error = %v", err)
	}
	if got.Priority != 7 || got.Preference != 42 {
		t.Errorf("Priority=%d Preference=%d, want 7/42", got.Priority, got.Preference)
	}
}

func TestGetSRCandidatePathName_Present(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: SRCandidatePathNameType, Length: 8, Value: []byte("mypolicy")}}}
	got, err := nlri.GetSRCandidatePathName()
	if err != nil {
		t.Fatalf("GetSRCandidatePathName() error = %v", err)
	}
	if got.SymbolicName != "mypolicy" {
		t.Errorf("SymbolicName = %q, want mypolicy", got.SymbolicName)
	}
}

func TestGetSRCandidatePathConstraints_Present(t *testing.T) {
	val := make([]byte, 8)
	val[0] = 0x80                           // FlagD
	binary.BigEndian.PutUint16(val[2:4], 5) // MTID=5
	val[4] = 128                            // Algo
	nlri := &NLRI{LS: []TLV{{Type: SRCandidatePathConstraintsType, Length: 8, Value: val}}}
	got, err := nlri.GetSRCandidatePathConstraints()
	if err != nil {
		t.Fatalf("GetSRCandidatePathConstraints() error = %v", err)
	}
	if !got.FlagD {
		t.Error("FlagD should be set")
	}
	if got.Algo != 128 {
		t.Errorf("Algo = %d, want 128", got.Algo)
	}
}

func TestGetFlexAlgoDefinition_Present(t *testing.T) {
	// 4-byte base: alg=128, calc=0, prio=0, res=0
	val := []byte{128, 0, 0, 0}
	nlri := &NLRI{LS: []TLV{{Type: 1039, Length: 4, Value: val}}}
	got, err := nlri.GetFlexAlgoDefinition()
	if err != nil {
		t.Fatalf("GetFlexAlgoDefinition() error = %v", err)
	}
	if len(got) != 1 || got[0].FlexAlgorithm != 128 {
		t.Errorf("GetFlexAlgoDefinition() = %v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UnmarshalAppSpecLinkAttr
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalAppSpecLinkAttr(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		checkFn func(*testing.T, *AppSpecLinkAttr)
	}{
		{
			name:    "too short (3 bytes)",
			input:   []byte{0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "invalid SAIBMLen value (e.g. 1 — not 0/4/8)",
			input:   []byte{0x01, 0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "invalid UDAIBMLen value",
			input:   []byte{0x00, 0x02, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:  "both sizes zero, no sub-TLVs",
			input: []byte{0x00, 0x00, 0x00, 0x00},
			checkFn: func(t *testing.T, a *AppSpecLinkAttr) {
				if a.SAIBMLen != 0 || a.UDAIBMLen != 0 {
					t.Error("expected zero bitmask lengths")
				}
			},
		},
		{
			name: "SAIBMLen=4, no UDAIBM",
			input: []byte{
				0x04, 0x00, // SAIBMLen=4, UDAIBMLen=0
				0x00, 0x00, // reserved
				0xDE, 0xAD, 0xBE, 0xEF, // SAIBM
			},
			checkFn: func(t *testing.T, a *AppSpecLinkAttr) {
				if len(a.SAIBM) != 4 {
					t.Errorf("SAIBM len = %d, want 4", len(a.SAIBM))
				}
				if a.SAIBM[0] != 0xDE || a.SAIBM[1] != 0xAD {
					t.Errorf("SAIBM = %v", a.SAIBM)
				}
			},
		},
		{
			name: "SAIBMLen=4, UDAIBMLen=4",
			input: []byte{
				0x04, 0x04,
				0x00, 0x00,
				0x01, 0x02, 0x03, 0x04, // SAIBM
				0xA, 0xB, 0xC, 0xD, // UDAIBM
			},
			checkFn: func(t *testing.T, a *AppSpecLinkAttr) {
				if len(a.SAIBM) != 4 || len(a.UDAIBM) != 4 {
					t.Errorf("SAIBM len=%d UDAIBM len=%d", len(a.SAIBM), len(a.UDAIBM))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalAppSpecLinkAttr(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalAppSpecLinkAttr() error = %v, wantErr %v", err, tt.wantErr)
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
// UnmarshalBGPLSNLRI happy path
// ─────────────────────────────────────────────────────────────────────────────

func TestUnmarshalBGPLSNLRI_Valid(t *testing.T) {
	// Build a single TLV 1026 (Node Name) with value "r1"
	b := []byte{
		0x04, 0x02, // type = 1026
		0x00, 0x02, // length = 2
		0x72, 0x31, // value = "r1"
	}
	nlri, err := UnmarshalBGPLSNLRI(b)
	if err != nil {
		t.Fatalf("UnmarshalBGPLSNLRI() error = %v", err)
	}
	if nlri.GetNodeName() != "r1" {
		t.Errorf("GetNodeName() = %q, want r1", nlri.GetNodeName())
	}
}

func TestUnmarshalBGPLSNLRI_MultiTLV(t *testing.T) {
	// TLV 1026 "r1" + TLV 1028 (local IPv4) 10.0.0.1
	b := []byte{
		0x04, 0x02, // type = 1026
		0x00, 0x02, // length = 2
		0x72, 0x31, // value = "r1"
		0x04, 0x04, // type = 1028
		0x00, 0x04, // length = 4
		0x0A, 0x00, 0x00, 0x01, // value = 10.0.0.1
	}
	nlri, err := UnmarshalBGPLSNLRI(b)
	if err != nil {
		t.Fatalf("UnmarshalBGPLSNLRI() error = %v", err)
	}
	if nlri.GetNodeName() != "r1" {
		t.Errorf("GetNodeName() = %q, want r1", nlri.GetNodeName())
	}
	if nlri.GetLocalIPv4RouterID() != "10.0.0.1" {
		t.Errorf("GetLocalIPv4RouterID() = %q, want 10.0.0.1", nlri.GetLocalIPv4RouterID())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetMTID with valid MTID bytes
// ─────────────────────────────────────────────────────────────────────────────

func TestGetMTID_Present(t *testing.T) {
	// base.UnmarshalMultiTopologyIdentifierTLV expects pairs of [2-byte MTID entries]
	// Each entry is a 2-byte big-endian value
	val := []byte{0x00, 0x02, 0x00, 0x04} // two MTIDs: 2 and 4
	nlri := &NLRI{LS: []TLV{{Type: 263, Length: 4, Value: val}}}
	got := nlri.GetMTID()
	if got == nil {
		t.Fatal("GetMTID() = nil, want non-nil")
	}
	if len(got) != 2 {
		t.Errorf("GetMTID() len = %d, want 2", len(got))
	}
}

func TestGetMTID_EmptyValue(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 263, Length: 0, Value: []byte{}}}}
	if got := nlri.GetMTID(); got != nil {
		t.Errorf("GetMTID() with empty value = %v, want nil", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Opaque Node/Link/Prefix Attribute getters - RFC 9552 §5.3.1.5/§5.3.2.6/§5.3.3.6
// ─────────────────────────────────────────────────────────────────────────────

func TestGetOpaqueNodeAttribute(t *testing.T) {
	tests := []struct {
		name string
		nlri *NLRI
		want []string
	}{
		{
			name: "absent returns nil",
			nlri: &NLRI{},
			want: nil,
		},
		{
			name: "wrong-type TLV ignored",
			nlri: &NLRI{LS: []TLV{{Type: 1097, Length: 2, Value: []byte{0xaa, 0xbb}}}},
			want: nil,
		},
		{
			name: "single TLV",
			nlri: &NLRI{LS: []TLV{{Type: 1025, Length: 4, Value: []byte{0xde, 0xad, 0xbe, 0xef}}}},
			want: []string{"deadbeef"},
		},
		{
			name: "multiple TLVs preserve order",
			nlri: &NLRI{LS: []TLV{
				{Type: 1025, Length: 2, Value: []byte{0x01, 0x02}},
				{Type: 1024, Length: 1, Value: []byte{0xff}}, // unrelated TLV between
				{Type: 1025, Length: 2, Value: []byte{0x03, 0x04}},
			}},
			want: []string{"0102", "0304"},
		},
		{
			name: "empty value encodes to empty hex",
			nlri: &NLRI{LS: []TLV{{Type: 1025, Length: 0, Value: []byte{}}}},
			want: []string{""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.nlri.GetOpaqueNodeAttribute()
			if !equalStringSlices(got, tc.want) {
				t.Errorf("GetOpaqueNodeAttribute() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetOpaqueLinkAttribute(t *testing.T) {
	// Different TLV type from Node, same shape: just verify dispatch is on 1097.
	nlri := &NLRI{LS: []TLV{
		{Type: 1025, Length: 1, Value: []byte{0xaa}}, // node opaque, must not match
		{Type: 1097, Length: 3, Value: []byte{0x11, 0x22, 0x33}},
		{Type: 1097, Length: 1, Value: []byte{0x44}},
	}}
	got := nlri.GetOpaqueLinkAttribute()
	want := []string{"112233", "44"}
	if !equalStringSlices(got, want) {
		t.Errorf("GetOpaqueLinkAttribute() = %v, want %v", got, want)
	}
	if absent := (&NLRI{}).GetOpaqueLinkAttribute(); absent != nil {
		t.Errorf("absent → %v, want nil", absent)
	}
}

func TestGetOpaquePrefixAttribute(t *testing.T) {
	nlri := &NLRI{LS: []TLV{{Type: 1157, Length: 2, Value: []byte{0xfe, 0xed}}}}
	got := nlri.GetOpaquePrefixAttribute()
	want := []string{"feed"}
	if !equalStringSlices(got, want) {
		t.Errorf("GetOpaquePrefixAttribute() = %v, want %v", got, want)
	}
	if absent := (&NLRI{}).GetOpaquePrefixAttribute(); absent != nil {
		t.Errorf("absent → %v, want nil", absent)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
