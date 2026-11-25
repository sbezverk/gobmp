package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestLSLinkUnidirectionalBandwidthPublication(t *testing.T) {
	tests := []struct {
		name     string
		tlvs     []lsSPFTLV
		wantKbps [3]string
		wantRaw  [3]string
	}{
		{
			name: "issue 537",
			tlvs: []lsSPFTLV{
				{1118, []byte{0x4e, 0x32, 0xd0, 0x5e}}, // 750,000,000 bytes/s
				{1119, []byte{0x4e, 0x26, 0xe4, 0x9c}}, // 700,000,000 bytes/s
				{1120, []byte{0x4d, 0x6e, 0x6b, 0x28}}, // 250,000,000 bytes/s
			},
			wantKbps: [3]string{"6000000", "5600000", "2000000"},
			wantRaw:  [3]string{"1311952990", "1311171740", "1299082024"},
		},
		{
			name: "above uint32, fractional kilobits, and zero",
			tlvs: []lsSPFTLV{
				{1118, []byte{0x53, 0x80, 0, 0}},    // 2^40 bytes/s
				{1119, []byte{0x43, 0x3b, 0x80, 0}}, // 187.5 bytes/s
				{1120, []byte{0, 0, 0, 0}},
			},
			wantKbps: [3]string{"8796093022", "1", "0"},
			wantRaw:  [3]string{"1400897536", "1127972864", ""},
		},
		{
			name: "exact truncation and uint64 limit",
			tlvs: []lsSPFTLV{
				{1118, []byte{0x5c, 0, 0, 0}},          // 2^57 bytes/s
				{1119, []byte{0x62, 0xf9, 0xff, 0xff}}, // Largest float32 below 125 × 2^64 bytes/s
				{1120, []byte{0x62, 0xfa, 0, 0}},       // 125 × 2^64 bytes/s
			},
			wantKbps: [3]string{"1152921504606846", "18446742947809644773", ""},
			wantRaw:  [3]string{"1543503872", "1660551167", "1660551168"},
		},
		{
			name: "missing and invalid lengths",
			tlvs: []lsSPFTLV{
				{1119, []byte{0x43, 0x3b, 0x80}},
				{1120, []byte{0x43, 0x3b, 0x80, 0, 0}},
			},
			wantRaw: [3]string{"", "", "1127972864"},
		},
		{
			name: "NaN, infinity, and negative",
			tlvs: []lsSPFTLV{
				{1118, []byte{0x7f, 0xc0, 0, 0}},
				{1119, []byte{0x7f, 0x80, 0, 0}},
				{1120, []byte{0xbf, 0x80, 0, 0}},
			},
			wantRaw: [3]string{"2143289344", "2139095040", "3212836864"},
		},
		{
			name: "overflow is omitted",
			tlvs: []lsSPFTLV{
				{1118, []byte{0x7f, 0x7f, 0xff, 0xff}},
			},
			wantRaw: [3]string{"2139095039", "", ""},
		},
	}

	reach := append([]byte{0x40, 4, 71, 4, 192, 0, 2, 2, 0}, testLSLinkNLRI80()...)
	nlri, err := bgp.UnmarshalMPReachNLRI(reach, false, nil)
	if err != nil {
		t.Fatalf("unmarshal BGP-LS MP_REACH_NLRI: %v", err)
	}
	fields := [...]string{"unidir_residual_bw", "unidir_available_bw", "unidir_bw_utilization"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			p.processMPUpdate(nlri, AddPrefix, minimalPeerHeader(), testLSUpdate(tt.tlvs...))

			if len(publisher.msgs) != 1 || publisher.msgs[0].msgType != bmp.LSLinkMsg {
				t.Fatalf("published %+v, want one BGP-LS Link message", publisher.msgs)
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal(publisher.msgs[0].payload, &got); err != nil {
				t.Fatalf("decode Link JSON: %v", err)
			}
			for i, field := range fields {
				if value := string(got[field+"_kbps"]); value != tt.wantKbps[i] {
					t.Errorf("%s_kbps = %q, want %q (raw %s = %s)", field, value, tt.wantKbps[i], field, got[field])
				}
				if value := string(got[field]); value != tt.wantRaw[i] {
					t.Errorf("%s = %q, want %q", field, value, tt.wantRaw[i])
				}
			}
		})
	}
}
