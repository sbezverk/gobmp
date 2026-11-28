package message

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// srv6InfoFixed is the 21 octets preceding the Sub-Sub-TLVs of an SRv6 SID
// Information Sub-TLV (RFC 9252 §3.1): SID 2001:db8:1:1::, behavior End.DT4.
func srv6InfoFixed() []byte {
	return []byte{0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 19, 0x00}
}

// srv6SIDStructure is a SID Structure Sub-Sub-TLV (RFC 9252 §3.2.1).
func srv6SIDStructure() []byte { return []byte{0x01, 0x00, 0x06, 40, 24, 16, 0, 16, 64} }

// srv6ShortSIDStructure is a SID Structure Sub-Sub-TLV of length five.
func srv6ShortSIDStructure() []byte { return []byte{0x01, 0x00, 0x05, 40, 24, 16, 0, 16} }

// srv6PrefixSIDValue returns a Prefix-SID attribute value holding one SRv6 L3
// Service TLV whose Sub-TLVs are subTLVs.
func srv6PrefixSIDValue(subTLVs []byte) []byte {
	return append([]byte{0x05, 0x00, byte(len(subTLVs) + 1), 0x00}, subTLVs...)
}

func srv6InfoSubTLV(value []byte) []byte {
	return append([]byte{0x01, 0x00, byte(len(value))}, value...)
}

// srv6Payloads publishes the UPDATE made of the path attributes attrs, which
// carries two routes, and returns the published messages of type msgType.
func srv6Payloads(t *testing.T, msgType int, attrs [][]byte) [][]byte {
	t.Helper()
	ph := benchPeerHeader()
	pub := &recordingPublisher{}
	p := NewProducer(pub, true).(*producer)
	p.producingWorker(benchPeerUp(ph))
	n := len(pub.msgs)
	p.producingWorker(routeMonitor(t, ph, afiBenchCase{name: t.Name(), update: benchUpdate(attrs, nil)}))

	var payloads [][]byte
	for _, m := range pub.msgs[n:] {
		if m.msgType != msgType {
			t.Fatalf("producingWorker(%x) message type = %d, want %d", attrs, m.msgType, msgType)
		}
		payloads = append(payloads, m.payload)
	}
	if len(payloads) != 2 {
		t.Fatalf("producingWorker(%x) = %d routes, want 2", attrs, len(payloads))
	}
	return payloads
}

// srv6VPNPayloads publishes two VPNv4 routes carried with the Prefix-SID
// attribute value psid and returns the published messages.
func srv6VPNPayloads(t *testing.T, psid []byte, withdraw bool) [][]byte {
	t.Helper()
	nlri := benchVPNPrefix([]byte{0x00, 0x10, 0x01})
	var attrs [][]byte
	if withdraw {
		nlri = benchVPNPrefix([]byte{0x80, 0x00, 0x00})
		attrs = [][]byte{benchPathAttr(benchOptional, bgp.MP_UNREACH_NLRI,
			append([]byte{0x00, 0x01, 128}, benchRepeat(2, nlri)...))}
	} else {
		attrs = append(benchCommonAttrs(nil), benchMPReach(1, 128, benchVPNNH6, benchRepeat(2, nlri)))
	}
	return srv6Payloads(t, bmp.L3VPNV4Msg, append(attrs, benchPathAttr(benchOptionalTra, 40, psid)))
}

// RFC 9252 §7 requires treat-as-withdraw for a malformed SRv6 Service TLV. That
// is not implemented: the "add" action asserted here is a known deviation, and
// only the removal of the decoded Prefix-SID is the intended behavior.
func TestMalformedSRv6L3ServiceDropsPrefixSIDWithoutTreatAsWithdraw(t *testing.T) {
	withTail := func(tail ...[]byte) []byte { return slices.Concat(append([][]byte{srv6InfoFixed()}, tail...)...) }
	// A second Information Sub-TLV, whose octets an overlong Sub-Sub-TLV length
	// in the first would otherwise read.
	next := srv6InfoSubTLV(srv6InfoFixed())
	valid := srv6PrefixSIDValue(next)

	tests := []struct {
		name string
		psid []byte
	}{
		{"a Sub-Sub-TLV header of one octet is rejected",
			srv6PrefixSIDValue(srv6InfoSubTLV(withTail([]byte{0x01})))},
		{"a Sub-Sub-TLV header of two octets is rejected",
			srv6PrefixSIDValue(srv6InfoSubTLV(withTail([]byte{0x01, 0x00})))},
		{"a short header after a SID Structure is rejected",
			srv6PrefixSIDValue(srv6InfoSubTLV(withTail(srv6SIDStructure(), []byte{0x02})))},
		{"a SID Structure length past the end of the attribute is rejected",
			srv6PrefixSIDValue(srv6InfoSubTLV(withTail([]byte{0x01, 0x00, 0x06})))},
		{"a SID Structure length reaching into the next Sub-TLV is rejected",
			srv6PrefixSIDValue(append(srv6InfoSubTLV(withTail([]byte{0x01, 0x00, 0x06, 40, 24})), next...))},
		{"an unknown Sub-Sub-TLV length past the end of the attribute is rejected",
			srv6PrefixSIDValue(srv6InfoSubTLV(withTail([]byte{0x02, 0xff, 0xff})))},
		{"an unknown Sub-Sub-TLV length reaching into the next Sub-TLV is rejected",
			srv6PrefixSIDValue(append(srv6InfoSubTLV(withTail([]byte{0x02, 0x00, 0x04})), next...))},
		{"an overrunning length after a short SID Structure is rejected",
			srv6PrefixSIDValue(srv6InfoSubTLV(withTail(srv6ShortSIDStructure(), []byte{0x02, 0x00, 0x04})))},
		{"an Information Sub-TLV of length zero is rejected",
			srv6PrefixSIDValue(srv6InfoSubTLV(nil))},
		{"an Information Sub-TLV without the trailing reserved octet is rejected",
			srv6PrefixSIDValue(srv6InfoSubTLV(srv6InfoFixed()[:20]))},
		{"an L3 Service TLV of length zero is rejected",
			[]byte{0x05, 0x00, 0x00}},
		{"a malformed first L3 Service TLV is not replaced by a valid second one",
			slices.Concat(srv6PrefixSIDValue(srv6InfoSubTLV(nil)), valid)},
		{"a second L3 Service TLV running past the end of the attribute is rejected",
			slices.Concat(valid, []byte{0x05, 0x00, 0x10, 0x00})},
	}
	for _, tt := range tests {
		for _, withdraw := range []bool{false, true} {
			action := "add"
			if withdraw {
				action = "del"
			}
			t.Run(tt.name+" on "+action, func(t *testing.T) {
				for i, payload := range srv6VPNPayloads(t, tt.psid, withdraw) {
					var r L3VPNPrefix
					if err := json.Unmarshal(payload, &r); err != nil {
						t.Fatalf("producingWorker(%x) payload %s: decode error %v, want a route", tt.psid, payload, err)
					}
					want := []string{"10.0.0.0", "10.0.1.0"}[i]
					if r.Action != action || r.Prefix != want || r.PrefixLen != 24 || r.VPNRD != "65001:1" {
						t.Errorf("producingWorker(%x) = %s %s/%d RD %s, want %s %s/24 RD 65001:1",
							tt.psid, r.Action, r.Prefix, r.PrefixLen, r.VPNRD, action, want)
					}
					if r.PrefixSID != nil {
						t.Errorf("producingWorker(%x) prefix_sid = %+v, want none", tt.psid, r.PrefixSID)
					}
					if r.BaseAttributes != nil && r.BaseAttributes.PrefixSID != nil {
						t.Errorf("producingWorker(%x) base_attrs.prefix_sid = %+v, want none", tt.psid, r.BaseAttributes.PrefixSID)
					}
				}
			})
		}
	}
}

// The "add" action is the same known deviation from RFC 9252 §7 as above.
func TestMalformedSRv6L3ServiceOnLabeledUnicastDropsPrefixSIDWithoutTreatAsWithdraw(t *testing.T) {
	psid := srv6PrefixSIDValue(srv6InfoSubTLV(srv6InfoFixed()[:20]))
	attr := benchPathAttr(benchOptionalTra, 40, psid)
	// Two /32 routes under the withdrawal label field 0x800000 (RFC 8277 §2.4).
	withdrawn := []byte{56, 0x80, 0, 0, 10, 255, 0, 0, 56, 0x80, 0, 0, 10, 255, 0, 1}
	tests := []struct {
		name   string
		action string
		attrs  [][]byte
	}{
		{"an announcement is published without a Prefix-SID", "add",
			append(benchCommonAttrs(nil), benchMPReach(1, 4, benchV4NH, benchRepeat(2, benchLUPrefix)), attr)},
		{"a withdrawal is published without a Prefix-SID", "del",
			[][]byte{benchPathAttr(benchOptional, bgp.MP_UNREACH_NLRI, append([]byte{0x00, 0x01, 4}, withdrawn...)), attr}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, payload := range srv6Payloads(t, bmp.UnicastPrefixV4Msg, tt.attrs) {
				var r UnicastPrefix
				if err := json.Unmarshal(payload, &r); err != nil {
					t.Fatalf("producingWorker(%x) payload %s: decode error %v, want a route", psid, payload, err)
				}
				want := []string{"10.255.0.0", "10.255.0.1"}[i]
				if r.Action != tt.action || r.Prefix != want || r.PrefixLen != 32 {
					t.Errorf("producingWorker(%x) = %s %s/%d, want %s %s/32", psid, r.Action, r.Prefix, r.PrefixLen, tt.action, want)
				}
				if r.PrefixSID != nil {
					t.Errorf("producingWorker(%x) prefix_sid = %+v, want none", psid, r.PrefixSID)
				}
				if r.BaseAttributes == nil || r.BaseAttributes.PrefixSID != nil || r.BaseAttributes.BGPPrefixSID == nil {
					t.Errorf("producingWorker(%x) base_attrs = %+v, want bgp_prefix_sid and no prefix_sid", psid, r.BaseAttributes)
				}
			}
		})
	}
}

func TestSIDStructureOfWrongLengthLeavesTheRestOfThePrefixSID(t *testing.T) {
	// Two Information Sub-TLVs, the first with a short SID Structure, followed by
	// the Label-Index and Originator SRGB TLVs (RFC 8669 §3).
	second := srv6InfoFixed()
	second[16] = 2 // SID 2001:db8:1:1::2
	psid := slices.Concat(
		srv6PrefixSIDValue(slices.Concat(
			srv6InfoSubTLV(append(srv6InfoFixed(), srv6ShortSIDStructure()...)),
			srv6InfoSubTLV(append(second, srv6SIDStructure()...)))),
		[]byte{0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4},
		[]byte{0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x3e, 0x80, 0x00, 0x1f, 0x40})
	var want any
	if err := json.Unmarshal([]byte(`{"label_index":{"last_index":164},`+
		`"originator_srgb":{"srgb":[{"first":16000,"number":8000}]},`+
		`"srv6_l3_service":{"sub_tlvs":{"1":[{"sid":"2001:db8:1:1::","endpoint_behavior":19},`+
		`{"sid":"2001:db8:1:1::2","endpoint_behavior":19,"sub_sub_tlvs":{"1":[{"locator_block_length":40,`+
		`"locator_node_length":24,"function_length":16,"argument_length":0,"transposition_length":16,`+
		`"transposition_offset":64}]}}]}}}`), &want); err != nil {
		t.Fatalf("json.Unmarshal(wanted prefix_sid) error = %v, want nil", err)
	}

	for i, payload := range srv6VPNPayloads(t, psid, false) {
		var got struct {
			Action    string `json:"action"`
			Prefix    string `json:"prefix"`
			PrefixSID any    `json:"prefix_sid"`
			BaseAttrs struct {
				PrefixSID any `json:"prefix_sid"`
			} `json:"base_attrs"`
		}
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("producingWorker(%x) payload %s: decode error %v, want a route", psid, payload, err)
		}
		wantPrefix := []string{"10.0.0.0", "10.0.1.0"}[i]
		if got.Action != "add" || got.Prefix != wantPrefix {
			t.Errorf("producingWorker(%x) = %s %s, want add %s", psid, got.Action, got.Prefix, wantPrefix)
		}
		if !reflect.DeepEqual(got.PrefixSID, want) {
			t.Errorf("producingWorker(%x) prefix_sid = %v, want %v", psid, got.PrefixSID, want)
		}
		if !reflect.DeepEqual(got.BaseAttrs.PrefixSID, want) {
			t.Errorf("producingWorker(%x) base_attrs.prefix_sid = %v, want %v", psid, got.BaseAttrs.PrefixSID, want)
		}
	}
}

func TestWellFormedSRv6L3ServiceIsPublishedOnEveryRoute(t *testing.T) {
	const structure = `{"locator_block_length":40,"locator_node_length":24,"function_length":16,` +
		`"argument_length":0,"transposition_length":16,"transposition_offset":64}`
	other := srv6InfoFixed()
	other[16] = 2 // SID 2001:db8:1:1::2
	tests := []struct {
		name        string
		tail        []byte
		later       []byte // octets following the first L3 Service TLV
		wantSubSubs string
	}{
		{name: "an Information Sub-TLV of the minimum length has no Sub-Sub-TLVs"},
		{name: "a SID Structure of length six is published", tail: srv6SIDStructure(),
			wantSubSubs: `,"sub_sub_tlvs":{"1":[` + structure + `]}`},
		{name: "an unknown Sub-Sub-TLV of length zero is published empty", tail: []byte{0x02, 0x00, 0x00},
			wantSubSubs: `,"sub_sub_tlvs":{"2":[""]}`},
		{name: "a SID Structure of length zero is left out", tail: []byte{0x01, 0x00, 0x00}},
		{name: "a SID Structure of length five is left out", tail: srv6ShortSIDStructure()},
		{name: "a SID Structure of length seven is left out",
			tail: []byte{0x01, 0x00, 0x07, 40, 24, 16, 0, 16, 64, 0}},
		{name: "a SID Structure after one of the wrong length is published",
			tail:        slices.Concat(srv6ShortSIDStructure(), srv6SIDStructure()),
			wantSubSubs: `,"sub_sub_tlvs":{"1":[` + structure + `]}`},
		{name: "a second valid L3 Service TLV is ignored", later: srv6PrefixSIDValue(srv6InfoSubTLV(other))},
		{name: "a second malformed L3 Service TLV is ignored",
			later: srv6PrefixSIDValue(srv6InfoSubTLV(other[:20]))},
		{name: "a second L3 Service TLV of length zero is ignored", later: []byte{0x05, 0x00, 0x00}},
	}
	for _, tt := range tests {
		psid := append(srv6PrefixSIDValue(srv6InfoSubTLV(append(srv6InfoFixed(), tt.tail...))), tt.later...)
		var want any
		if err := json.Unmarshal([]byte(`{"srv6_l3_service":{"sub_tlvs":{"1":[{"sid":"2001:db8:1:1::","endpoint_behavior":19`+
			tt.wantSubSubs+`}]}}}`), &want); err != nil {
			t.Fatalf("json.Unmarshal(wanted prefix_sid of %q) error = %v, want nil", tt.name, err)
		}
		for _, withdraw := range []bool{false, true} {
			action := "add"
			if withdraw {
				action = "del"
			}
			t.Run(tt.name+" on "+action, func(t *testing.T) {
				for _, payload := range srv6VPNPayloads(t, psid, withdraw) {
					var got struct {
						Action    string `json:"action"`
						PrefixSID any    `json:"prefix_sid"`
						BaseAttrs struct {
							PrefixSID any `json:"prefix_sid"`
						} `json:"base_attrs"`
					}
					if err := json.Unmarshal(payload, &got); err != nil {
						t.Fatalf("producingWorker(%x) payload %s: decode error %v, want a route", psid, payload, err)
					}
					if got.Action != action {
						t.Errorf("producingWorker(%x) action = %q, want %q", psid, got.Action, action)
					}
					if !reflect.DeepEqual(got.PrefixSID, want) {
						t.Errorf("producingWorker(%x) prefix_sid = %v, want %v", psid, got.PrefixSID, want)
					}
					if !reflect.DeepEqual(got.BaseAttrs.PrefixSID, want) {
						t.Errorf("producingWorker(%x) base_attrs.prefix_sid = %v, want %v", psid, got.BaseAttrs.PrefixSID, want)
					}
				}
			})
		}
	}
}
