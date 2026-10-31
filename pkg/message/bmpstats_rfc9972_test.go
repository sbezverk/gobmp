package message

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// buildStatsReport encodes TLVs as a wire-format Stats Report and parses it.
func buildStatsReport(t *testing.T, tlvs ...[]byte) *bmp.StatsReport {
	t.Helper()
	b := binary.BigEndian.AppendUint32(nil, uint32(len(tlvs)))
	for _, tlv := range tlvs {
		b = append(b, tlv...)
	}
	sr, err := bmp.UnmarshalBMPStatsReportMessage(b)
	if err != nil {
		t.Fatalf("UnmarshalBMPStatsReportMessage() error = %v", err)
	}
	return sr
}

func wireTLV(typ uint16, val []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(val)))
	return append(b, val...)
}

// publishStats runs the producer and returns the decoded published Stats.
func publishStats(t *testing.T, sr *bmp.StatsReport) Stats {
	t.Helper()
	rec := &recordingPublisher{}
	p := &producer{publisher: rec}
	p.produceStatsMessage(bmp.Message{PeerHeader: statsTestPeerHeader(), Payload: sr})
	if len(rec.msgs) != 1 {
		t.Fatalf("published %d messages, want 1", len(rec.msgs))
	}
	var got Stats
	if err := json.Unmarshal(rec.msgs[0].payload, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return got
}

var rfc9972GlobalCases = []struct {
	typ  uint16
	val  uint64
	key  string
	read func(Stats) uint64
}{
	{18, 1801, "pre_policy_adj_rib_in", func(s Stats) uint64 { return s.PrePolicyAdjRIBIn }},
	{20, 2002, "post_policy_adj_rib_in", func(s Stats) uint64 { return s.PostPolicyAdjRIBIn }},
	{29, 2903, "post_policy_adj_rib_in_threshold_left", func(s Stats) uint64 { return s.PostPolicyAdjRIBInThresholdLeft }},
	{31, 3104, "license_threshold_left", func(s Stats) uint64 { return s.LicenseThresholdLeft }},
	{33, 3305, "pre_policy_adj_rib_in_aspath_too_long", func(s Stats) uint64 { return s.PrePolicyAdjRIBInASPathTooLong }},
	{39, 3906, "pre_policy_adj_rib_out_aspath_too_long", func(s Stats) uint64 { return s.PrePolicyAdjRIBOutASPathTooLong }},
}

func TestRFC9972GlobalTypes(t *testing.T) {
	tests := rfc9972GlobalCases
	var tlvs [][]byte
	for _, tt := range tests {
		tlvs = append(tlvs, wireTLV(tt.typ, uint64Bytes(tt.val)))
	}
	got := publishStats(t, buildStatsReport(t, tlvs...))
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var kv map[string]any
	if err := json.Unmarshal(raw, &kv); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	for _, tt := range tests {
		if v := tt.read(got); v != tt.val {
			t.Errorf("type %d: got %d, want %d", tt.typ, v, tt.val)
		}
		if v, ok := kv[tt.key].(float64); !ok || uint64(v) != tt.val {
			t.Errorf("type %d: json key %q = %v, want %d", tt.typ, tt.key, kv[tt.key], tt.val)
		}
	}
}

var rfc9972PerAFICases = []struct {
	typ  uint16
	key  string
	read func(*Stats) []AFISAFIStat
}{
	{19, "per_afi_pre_policy_adj_rib_in", func(s *Stats) []AFISAFIStat { return s.PerAFIPrePolicyAdjRIBIn }},
	{21, "per_afi_post_policy_adj_rib_in", func(s *Stats) []AFISAFIStat { return s.PerAFIPostPolicyAdjRIBIn }},
	{22, "per_afi_pre_policy_adj_rib_in_rejected", func(s *Stats) []AFISAFIStat { return s.PerAFIPrePolicyAdjRIBInRejected }},
	{23, "per_afi_post_policy_adj_rib_in_accepted", func(s *Stats) []AFISAFIStat { return s.PerAFIPostPolicyAdjRIBInAccepted }},
	{26, "per_afi_route_damping_suppressed", func(s *Stats) []AFISAFIStat { return s.PerAFIRouteDampingSuppressed }},
	{27, "per_afi_gr_stale", func(s *Stats) []AFISAFIStat { return s.PerAFIGRStale }},
	{28, "per_afi_llgr_stale", func(s *Stats) []AFISAFIStat { return s.PerAFILLGRStale }},
	{30, "per_afi_post_policy_adj_rib_in_threshold_left", func(s *Stats) []AFISAFIStat { return s.PerAFIPostPolicyAdjRIBInThresholdLeft }},
	{32, "per_afi_license_threshold_left", func(s *Stats) []AFISAFIStat { return s.PerAFILicenseThresholdLeft }},
	{34, "per_afi_pre_policy_adj_rib_in_aspath_too_long", func(s *Stats) []AFISAFIStat { return s.PerAFIPrePolicyAdjRIBInASPathTooLong }},
	{35, "per_afi_post_policy_adj_rib_in_rpki_invalid", func(s *Stats) []AFISAFIStat { return s.PerAFIPostPolicyAdjRIBInRPKIInvalid }},
	{36, "per_afi_post_policy_adj_rib_in_rpki_valid", func(s *Stats) []AFISAFIStat { return s.PerAFIPostPolicyAdjRIBInRPKIValid }},
	{37, "per_afi_post_policy_adj_rib_in_rpki_not_found", func(s *Stats) []AFISAFIStat { return s.PerAFIPostPolicyAdjRIBInRPKINotFound }},
	{38, "per_afi_pre_policy_adj_rib_out_rejected", func(s *Stats) []AFISAFIStat { return s.PerAFIPrePolicyAdjRIBOutRejected }},
	{40, "per_afi_pre_policy_adj_rib_out_aspath_too_long", func(s *Stats) []AFISAFIStat { return s.PerAFIPrePolicyAdjRIBOutASPathTooLong }},
	{41, "per_afi_post_policy_adj_rib_out_rpki_invalid", func(s *Stats) []AFISAFIStat { return s.PerAFIPostPolicyAdjRIBOutRPKIInvalid }},
	{42, "per_afi_post_policy_adj_rib_out_rpki_valid", func(s *Stats) []AFISAFIStat { return s.PerAFIPostPolicyAdjRIBOutRPKIValid }},
	{43, "per_afi_post_policy_adj_rib_out_rpki_not_found", func(s *Stats) []AFISAFIStat { return s.PerAFIPostPolicyAdjRIBOutRPKINotFound }},
}

func TestRFC9972PerAFITypes(t *testing.T) {
	tests := rfc9972PerAFICases
	var tlvs [][]byte
	want := make(map[uint16][]AFISAFIStat)
	for _, tt := range tests {
		// Two entries per type, distinct per type, to show both are appended.
		a := AFISAFIStat{AFI: 1, SAFI: uint8(tt.typ), Count: uint64(tt.typ) * 100}
		b := AFISAFIStat{AFI: 2, SAFI: uint8(tt.typ) + 1, Count: uint64(tt.typ)*100 + 1}
		want[tt.typ] = []AFISAFIStat{a, b}
		tlvs = append(tlvs,
			wireTLV(tt.typ, makeAFISAFIData(a.AFI, a.SAFI, a.Count)),
			wireTLV(tt.typ, makeAFISAFIData(b.AFI, b.SAFI, b.Count)))
	}
	got := publishStats(t, buildStatsReport(t, tlvs...))
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var kv map[string]json.RawMessage
	if err := json.Unmarshal(raw, &kv); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	for _, tt := range tests {
		if g := tt.read(&got); !reflect.DeepEqual(g, want[tt.typ]) {
			t.Errorf("type %d: got %v, want %v", tt.typ, g, want[tt.typ])
		}
		var g []AFISAFIStat
		if err := json.Unmarshal(kv[tt.key], &g); err != nil || !reflect.DeepEqual(g, want[tt.typ]) {
			t.Errorf("type %d: json key %q = %s (err %v), want %v", tt.typ, tt.key, kv[tt.key], err, want[tt.typ])
		}
	}
}

// TestType9WrongLengthRejected checks the shared parseAFISAFIStat exact length
// on type 9, whose value is 2-byte AFI, 1-byte SAFI and a 64-bit Gauge
// (RFC 7854 Section 4.8).
func TestType9WrongLengthRejected(t *testing.T) {
	for _, n := range []int{10, 12} {
		t.Run(fmt.Sprintf("len_%d", n), func(t *testing.T) {
			got := publishStats(t, buildStatsReport(t,
				wireTLV(9, bytes.Repeat([]byte{0xff}, n)),
				wireTLV(18, uint64Bytes(5))))
			if got.PerAFIAdjRIBsIn != nil || got.PrePolicyAdjRIBIn != 5 {
				t.Errorf("got type9=%v type18=%d, want nil and 5", got.PerAFIAdjRIBsIn, got.PrePolicyAdjRIBIn)
			}
		})
	}
	got := publishStats(t, buildStatsReport(t, wireTLV(9, makeAFISAFIData(2, 1, 88))))
	if want := []AFISAFIStat{{AFI: 2, SAFI: 1, Count: 88}}; !reflect.DeepEqual(got.PerAFIAdjRIBsIn, want) {
		t.Errorf("PerAFIAdjRIBsIn = %v, want %v", got.PerAFIAdjRIBsIn, want)
	}
}

// TestRFC9972WrongLengthRejected checks RFC 9972 Section 3.1 exact Stat Len:
// a TLV of any other length is skipped (key absent), and the TLVs around it
// in the same report are still decoded.
func TestRFC9972WrongLengthRejected(t *testing.T) {
	// sentinel is a valid global TLV of a type not under test, proving the report survives.
	const sentinelType, sentinelVal = 20, 777
	jsonKeys := func(t *testing.T, s Stats) map[string]json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		var kv map[string]json.RawMessage
		if err := json.Unmarshal(raw, &kv); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		return kv
	}
	for _, tt := range rfc9972GlobalCases {
		if tt.typ == sentinelType {
			continue
		}
		for _, n := range []int{7, 9, 16} {
			t.Run(fmt.Sprintf("global_type_%d_len_%d", tt.typ, n), func(t *testing.T) {
				// Nonzero bytes so a partial decode of the first 8 would be visible.
				val := bytes.Repeat([]byte{0xff}, n)
				got := publishStats(t, buildStatsReport(t,
					wireTLV(tt.typ, val),
					wireTLV(sentinelType, uint64Bytes(sentinelVal))))
				if v := tt.read(got); v != 0 {
					t.Errorf("rejected TLV populated field: %d", v)
				}
				kv := jsonKeys(t, got)
				if _, ok := kv[tt.key]; ok {
					t.Errorf("json key %q present for len %d", tt.key, n)
				}
				if got.PostPolicyAdjRIBIn != sentinelVal {
					t.Errorf("sentinel = %d, want %d", got.PostPolicyAdjRIBIn, sentinelVal)
				}
			})
		}
	}
	for _, tt := range rfc9972PerAFICases {
		for _, n := range []int{10, 12} {
			t.Run(fmt.Sprintf("per_afi_type_%d_len_%d", tt.typ, n), func(t *testing.T) {
				val := bytes.Repeat([]byte{0xff}, n)
				got := publishStats(t, buildStatsReport(t,
					wireTLV(tt.typ, val),
					wireTLV(sentinelType, uint64Bytes(sentinelVal))))
				if v := tt.read(&got); v != nil {
					t.Errorf("rejected TLV populated field: %v", v)
				}
				kv := jsonKeys(t, got)
				if _, ok := kv[tt.key]; ok {
					t.Errorf("json key %q present for len %d", tt.key, n)
				}
				if got.PostPolicyAdjRIBIn != sentinelVal {
					t.Errorf("sentinel = %d, want %d", got.PostPolicyAdjRIBIn, sentinelVal)
				}
			})
		}
	}
	// Type 20 is the sentinel above, so cover its wrong lengths here.
	for _, n := range []int{7, 9, 16} {
		t.Run(fmt.Sprintf("global_type_20_len_%d", n), func(t *testing.T) {
			got := publishStats(t, buildStatsReport(t,
				wireTLV(20, bytes.Repeat([]byte{0xff}, n)),
				wireTLV(18, uint64Bytes(5))))
			if got.PostPolicyAdjRIBIn != 0 || got.PrePolicyAdjRIBIn != 5 {
				t.Errorf("got type20=%d type18=%d, want 0 and 5", got.PostPolicyAdjRIBIn, got.PrePolicyAdjRIBIn)
			}
		})
	}
}

func TestNonRFC9972TypesIgnored(t *testing.T) {
	got := publishStats(t, buildStatsReport(t,
		wireTLV(24, uint64Bytes(5)),
		wireTLV(25, makeAFISAFIData(1, 1, 6)),
		wireTLV(18, uint64Bytes(42)),
	))
	want := Stats{PrePolicyAdjRIBIn: 42}
	// Compare only the stat fields; header fields are set by the producer.
	got.RouterHash, got.RouterIP, got.PeerType, got.RemoteBGPID, got.RemoteIP, got.RemoteASN, got.PeerRD, got.Timestamp, got.Key, got.ID = "", "", 0, "", "", 0, "", "", "", ""
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
