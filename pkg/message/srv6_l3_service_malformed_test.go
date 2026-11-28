package message

import (
	"encoding/json"
	"fmt"
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

// srv6VPNMsgTypes maps an AFI to the topic of its VPN routes.
var srv6VPNMsgTypes = map[uint16]int{1: bmp.L3VPNV4Msg, 2: bmp.L3VPNV6Msg}

// srv6VPNPrefix returns the VPN NLRI 10.0.i.0/24 for AFI 1 and
// 2001:db8:i::/48 for AFI 2, under label and RD 65001:1.
func srv6VPNPrefix(afi uint16, label []byte) func(int) []byte {
	if afi == 1 {
		return benchVPNPrefix(label)
	}
	return func(i int) []byte {
		return slices.Concat([]byte{24 + 64 + 48}, label, benchRD, []byte{0x20, 0x01, 0x0d, 0xb8, 0, byte(i)})
	}
}

// srv6VPNPayloads publishes two VPN routes of afi carried with the Prefix-SID
// attribute value psid and returns the published messages.
func srv6VPNPayloads(t *testing.T, afi uint16, psid []byte, withdraw bool) [][]byte {
	t.Helper()
	var attrs [][]byte
	if withdraw {
		nlri := benchRepeat(2, srv6VPNPrefix(afi, []byte{0x80, 0x00, 0x00}))
		attrs = [][]byte{benchPathAttr(benchOptional, bgp.MP_UNREACH_NLRI, append([]byte{0x00, byte(afi), 128}, nlri...))}
	} else {
		nlri := benchRepeat(2, srv6VPNPrefix(afi, []byte{0x00, 0x10, 0x01}))
		attrs = append(benchCommonAttrs(nil), benchMPReach(afi, 128, benchVPNNH6, nlri))
	}
	return srv6Payloads(t, srv6VPNMsgTypes[afi], append(attrs, benchPathAttr(benchOptionalTra, 40, psid)))
}

// srv6Route is the part of a published route these tests assert.
type srv6Route struct {
	Action    string         `json:"action"`
	Hash      string         `json:"hash"`
	Prefix    string         `json:"prefix"`
	PrefixLen int32          `json:"prefix_len"`
	VPNRD     string         `json:"vpn_rd"`
	IsEOR     bool           `json:"is_eor"`
	PrefixSID map[string]any `json:"prefix_sid"`
	BaseAttrs map[string]any `json:"base_attrs"`
}

func decodeSRv6Route(t *testing.T, payload []byte) srv6Route {
	t.Helper()
	var r srv6Route
	if err := json.Unmarshal(payload, &r); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v, want nil", payload, err)
	}
	return r
}

// RFC 9252 §7: a malformed SRv6 Service TLV withdraws every route of the UPDATE.
func TestMalformedSRv6ServiceTLVWithdrawsVPNRoutes(t *testing.T) {
	wantPrefixes := map[uint16][]string{1: {"10.0.0.0", "10.0.1.0"}, 2: {"2001:db8::", "2001:db8:1::"}}
	wantLengths := map[uint16]int32{1: 24, 2: 48}
	withTail := func(tail ...[]byte) []byte { return slices.Concat(append([][]byte{srv6InfoFixed()}, tail...)...) }
	// A second Information Sub-TLV, whose octets an overlong Sub-Sub-TLV length
	// in the first would otherwise read.
	next := srv6InfoSubTLV(srv6InfoFixed())
	// Label-Index TLVs (RFC 8669 §3.1) of length six and eight, and an Originator
	// SRGB TLV (RFC 8669 §3.2) of length one.
	shortLabelIndex := []byte{0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0}
	longLabelIndex := []byte{0x01, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0x05}
	shortSRGB := []byte{0x03, 0x00, 0x01, 0}

	// Service TLV types 5 (L3) and 6 (L2) share their structure.
	for _, service := range []struct {
		name      string
		typ       byte
		otherType byte
	}{{"L3", 5, 6}, {"L2", 6, 5}} {
		tlv := func(subTLVs []byte) []byte {
			v := srv6PrefixSIDValue(subTLVs)
			v[0] = service.typ
			return v
		}
		valid := tlv(next)
		otherValid := srv6PrefixSIDValue(next)
		otherValid[0] = service.otherType
		zeroLength := []byte{service.typ, 0x00, 0x00}

		tests := []struct {
			name string
			psid []byte
		}{
			{"a Sub-Sub-TLV header of one octet", tlv(srv6InfoSubTLV(withTail([]byte{0x01})))},
			{"a Sub-Sub-TLV header of two octets", tlv(srv6InfoSubTLV(withTail([]byte{0x01, 0x00})))},
			{"a short header after a SID Structure",
				tlv(srv6InfoSubTLV(withTail(srv6SIDStructure(), []byte{0x02})))},
			{"a SID Structure length past the end of the attribute",
				tlv(srv6InfoSubTLV(withTail([]byte{0x01, 0x00, 0x06})))},
			{"a SID Structure length reaching into the next Sub-TLV",
				tlv(append(srv6InfoSubTLV(withTail([]byte{0x01, 0x00, 0x06, 40, 24})), next...))},
			{"an unknown Sub-Sub-TLV length past the end of the attribute",
				tlv(srv6InfoSubTLV(withTail([]byte{0x02, 0xff, 0xff})))},
			{"an unknown Sub-Sub-TLV length reaching into the next Sub-TLV",
				tlv(append(srv6InfoSubTLV(withTail([]byte{0x02, 0x00, 0x04})), next...))},
			{"an overrunning length after a short SID Structure",
				tlv(srv6InfoSubTLV(withTail(srv6ShortSIDStructure(), []byte{0x02, 0x00, 0x04})))},
			{"an Information Sub-TLV of length zero", tlv(srv6InfoSubTLV(nil))},
			{"an Information Sub-TLV of length 20", tlv(srv6InfoSubTLV(srv6InfoFixed()[:20]))},
			{"a malformed second Information Sub-TLV", tlv(append(slices.Clone(next), srv6InfoSubTLV(nil)...))},
			{"a Sub-TLV header of two octets", tlv([]byte{0x01, 0x00})},
			{"an unknown Sub-TLV length past the end of the Service TLV",
				slices.Concat(tlv([]byte{0x09, 0x00, 0x04}), shortSRGB)},
			{"a Service TLV of length zero", zeroLength},
			{"a Service TLV header of one octet", []byte{service.typ}},
			{"a Service TLV header of two octets", []byte{service.typ, 0x00}},
			{"a Service TLV length past the end of the attribute", []byte{service.typ, 0x00, 0x10, 0x00}},
			{"a malformed first Service TLV before a valid one", slices.Concat(tlv(srv6InfoSubTLV(nil)), valid)},
			{"a second Service TLV running past the end of the attribute",
				slices.Concat(valid, []byte{service.typ, 0x00, 0x10, 0x00})},
			{"a malformed Service TLV after a valid one of the other type", slices.Concat(otherValid, zeroLength)},
			{"a malformed Service TLV after a Label-Index of length six",
				slices.Concat(shortLabelIndex, zeroLength)},
			{"a malformed Service TLV after a Label-Index of length eight",
				slices.Concat(longLabelIndex, zeroLength)},
			{"a malformed Service TLV after an Originator SRGB of length one",
				slices.Concat(shortSRGB, zeroLength)},
		}
		for _, tt := range tests {
			for _, afi := range []uint16{1, 2} {
				for _, withdraw := range []bool{false, true} {
					name := fmt.Sprintf("%s in an %s Service TLV withdraws AFI %d routes", tt.name, service.name, afi)
					if withdraw {
						name += " already in MP_UNREACH_NLRI"
					}
					t.Run(name, func(t *testing.T) {
						added := srv6VPNPayloads(t, afi, srv6PrefixSIDValue(next), false)
						for i, payload := range srv6VPNPayloads(t, afi, tt.psid, withdraw) {
							got := decodeSRv6Route(t, payload)
							wantHash := decodeSRv6Route(t, added[i]).Hash
							if got.Action != "del" || got.IsEOR || got.Hash == "" || got.Hash != wantHash {
								t.Errorf("producingWorker(%x) action, is_eor, hash = %q, %t, %q, want \"del\", false, %q",
									tt.psid, got.Action, got.IsEOR, got.Hash, wantHash)
							}
							if got.Prefix != wantPrefixes[afi][i] || got.PrefixLen != wantLengths[afi] || got.VPNRD != "65001:1" {
								t.Errorf("producingWorker(%x) route = %s/%d RD %s, want %s/%d RD 65001:1",
									tt.psid, got.Prefix, got.PrefixLen, got.VPNRD, wantPrefixes[afi][i], wantLengths[afi])
							}
							if got.BaseAttrs["srv6_service_malformed"] != true {
								t.Errorf("producingWorker(%x) base_attrs = %v, want srv6_service_malformed true", tt.psid, got.BaseAttrs)
							}
							if got.PrefixSID != nil || got.BaseAttrs["prefix_sid"] != nil {
								t.Errorf("producingWorker(%x) prefix_sid = %v and %v, want none",
									tt.psid, got.PrefixSID, got.BaseAttrs["prefix_sid"])
							}
						}
					})
				}
			}
		}
	}
}

// srv6LUWithdrawal is two /32 routes under the withdrawal label field 0x800000
// (RFC 8277 §2.4), as benchLUPrefix announces them.
var srv6LUWithdrawal = []byte{56, 0x80, 0, 0, 10, 255, 0, 0, 56, 0x80, 0, 0, 10, 255, 0, 1}

// A malformed SRv6 Service TLV calls for treat-as-withdraw (RFC 9252 §7) and,
// on labeled unicast, for attribute discard (RFC 8669 §6). The Prefix-SID is
// dropped and the stronger action applies, as RFC 7606 §3(h) rules when multiple
// attribute errors ask for different ones.
func TestMalformedSRv6ServiceTLVWithdrawsLabeledUnicastRoutes(t *testing.T) {
	bad := srv6PrefixSIDValue(srv6InfoSubTLV(srv6InfoFixed()[:20]))
	shortLabelIndex := []byte{0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0}
	reach := append(benchCommonAttrs(nil), benchMPReach(1, 4, benchV4NH, benchRepeat(2, benchLUPrefix)))
	unreach := [][]byte{benchPathAttr(benchOptional, bgp.MP_UNREACH_NLRI,
		append([]byte{0x00, 0x01, 4}, srv6LUWithdrawal...))}
	tests := []struct {
		name   string
		attrs  [][]byte
		psid   []byte
		legacy bool // bgp_prefix_sid is published
	}{
		{"an announcement is withdrawn", reach, bad, true},
		{"a withdrawal stays a withdrawal", unreach, bad, true},
		{"an announcement is withdrawn after a bad Label-Index", reach, slices.Concat(shortLabelIndex, bad), false},
		{"an announcement is withdrawn before a bad Label-Index", reach, slices.Concat(bad, shortLabelIndex), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			psid := tt.psid
			attrs := append(slices.Clone(tt.attrs), benchPathAttr(benchOptionalTra, 40, psid))
			for i, payload := range srv6Payloads(t, bmp.UnicastPrefixV4Msg, attrs) {
				got := decodeSRv6Route(t, payload)
				want := []string{"10.255.0.0", "10.255.0.1"}[i]
				if got.Action != "del" || got.Prefix != want || got.PrefixLen != 32 {
					t.Errorf("producingWorker(%x) = %s %s/%d, want del %s/32", psid, got.Action, got.Prefix, got.PrefixLen, want)
				}
				if got.PrefixSID != nil || got.BaseAttrs["prefix_sid"] != nil {
					t.Errorf("producingWorker(%x) prefix_sid = %v and %v, want none", psid, got.PrefixSID, got.BaseAttrs["prefix_sid"])
				}
				if got.BaseAttrs["srv6_service_malformed"] != true || (got.BaseAttrs["bgp_prefix_sid"] != nil) != tt.legacy {
					t.Errorf("producingWorker(%x) base_attrs = %v, want srv6_service_malformed and bgp_prefix_sid published %t",
						psid, got.BaseAttrs, tt.legacy)
				}
			}
		})
	}
}

// srv6ServiceJSON is the published form of the SRv6 L3 Service TLV which
// srv6PrefixSIDValue(srv6InfoSubTLV(srv6InfoFixed())) encodes.
const srv6ServiceJSON = `"srv6_l3_service":{"sub_tlvs":{"1":[{"sid":"2001:db8:1:1::","endpoint_behavior":19}]}}`

// srv6LUv6Prefix returns the labeled unicast NLRI 2001:db8:i::/48.
func srv6LUv6Prefix(i int) []byte {
	return []byte{24 + 48, 0x00, 0x10, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0, byte(i)}
}

// A Label-Index or Originator SRGB TLV of an invalid length discards the
// attribute on labeled unicast routes (RFC 8669 §6). Other families ignore those
// TLVs (RFC 8669 §3.1, §3.2), so only the bad one is left out.
func TestBadLabelIndexOrSRGBLengthDiscardsThePrefixSIDOfLabeledUnicastOnly(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
		want  string // prefix_sid of the VPN routes
		luSID bool   // labeled unicast routes publish it too
	}{
		{name: "a valid Label-Index", value: []byte{0x01, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0xa4},
			want: `{"label_index":{"last_index":164},` + srv6ServiceJSON + `}`, luSID: true},
		{name: "a Label-Index of length six", value: []byte{0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0},
			want: `{` + srv6ServiceJSON + `}`},
		// The eighth value octet is the type of an SRv6 L3 Service TLV.
		{name: "a Label-Index of length eight", value: []byte{0x01, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0x05},
			want: `{` + srv6ServiceJSON + `}`},
		{name: "an Originator SRGB of length one", value: []byte{0x03, 0x00, 0x01, 0},
			want: `{` + srv6ServiceJSON + `}`},
	}
	for _, tt := range tests {
		t.Run(tt.name+" leaves routes announced", func(t *testing.T) {
			psid := slices.Concat(tt.value, srv6PrefixSIDValue(srv6InfoSubTLV(srv6InfoFixed())))
			var want map[string]any
			if err := json.Unmarshal([]byte(tt.want), &want); err != nil {
				t.Fatalf("json.Unmarshal(%s) error = %v, want nil", tt.want, err)
			}
			check := func(family string, payloads [][]byte, root, base map[string]any) {
				t.Helper()
				for _, payload := range payloads {
					got := decodeSRv6Route(t, payload)
					if _, flagged := got.BaseAttrs["srv6_service_malformed"]; flagged || got.Action != "add" {
						t.Errorf("producingWorker(%x) %s action = %q, base_attrs = %v, want add without srv6_service_malformed",
							psid, family, got.Action, got.BaseAttrs)
					}
					gotBase, _ := got.BaseAttrs["prefix_sid"].(map[string]any)
					if !reflect.DeepEqual(got.PrefixSID, root) || !reflect.DeepEqual(gotBase, base) {
						t.Errorf("producingWorker(%x) %s prefix_sid, base_attrs.prefix_sid = %v, %v, want %v, %v",
							psid, family, got.PrefixSID, gotBase, root, base)
					}
				}
			}
			attr := benchPathAttr(benchOptionalTra, 40, psid)
			check("VPNv4", srv6VPNPayloads(t, 1, psid, false), want, want)
			check("VPNv6", srv6VPNPayloads(t, 2, psid, false), want, want)
			// Unicast routes carry the attribute in base_attrs only.
			check("unicast IPv4", srv6Payloads(t, bmp.UnicastPrefixV4Msg, append(benchCommonAttrs(nil),
				benchMPReach(1, 1, benchV4NH, benchRepeat(2, benchV4Prefix)), attr)), nil, want)
			if !tt.luSID {
				want = nil
			}
			check("labeled unicast IPv4", srv6Payloads(t, bmp.UnicastPrefixV4Msg, append(benchCommonAttrs(nil),
				benchMPReach(1, 4, benchV4NH, benchRepeat(2, benchLUPrefix)), attr)), want, want)
			check("labeled unicast IPv6", srv6Payloads(t, bmp.UnicastPrefixV6Msg, append(benchCommonAttrs(nil),
				benchMPReach(2, 4, benchV6NH, benchRepeat(2, srv6LUv6Prefix)), attr)), want, want)
		})
	}
}

// The labeled unicast discard (RFC 8669 §6) must not reach the other routes of
// the same UPDATE.
func TestLabeledUnicastPrefixSIDDiscardLeavesOtherRoutesAlone(t *testing.T) {
	psid := slices.Concat([]byte{0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0},
		srv6PrefixSIDValue(srv6InfoSubTLV(srv6InfoFixed())))
	body := benchUpdate(append(benchCommonAttrs(benchV4NH), benchMPReach(1, 4, benchV4NH, benchLUPrefix(0)),
		benchPathAttr(benchOptionalTra, 40, psid)), benchV4Prefix(1))

	msgs := srv6Publish(t, body)
	if len(msgs) != 2 {
		t.Fatalf("producingWorker(%x) published %d messages, want 2", body, len(msgs))
	}
	for i, wantSID := range []bool{false, true} { // labeled unicast, then legacy NLRI
		got := decodeSRv6Route(t, msgs[i].payload)
		if got.Action != "add" || (got.BaseAttrs["prefix_sid"] != nil) != wantSID {
			t.Errorf("producingWorker(%x) message %d action = %q, base_attrs.prefix_sid = %v, want add, published %t",
				body, i, got.Action, got.BaseAttrs["prefix_sid"], wantSID)
		}
	}

	update, err := bgp.UnmarshalBGPUpdate(body)
	if err != nil {
		t.Fatalf("UnmarshalBGPUpdate(%x) error = %v, want nil", body, err)
	}
	_, i := update.GetNLRIType()
	nlri, err := bgp.UnmarshalMPReachNLRI(update.PathAttributes[i].Attribute, false, nil)
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI(%x) error = %v, want nil", body, err)
	}
	routes, err := NewProducer(&recordingPublisher{}, true).(*producer).unicast(nlri, AddPrefix, benchPeerHeader(), update, true)
	if err != nil || len(routes) != 1 {
		t.Fatalf("unicast(%x) = %d routes, error %v, want 1 route", body, len(routes), err)
	}
	if routes[0].BaseAttributes.PrefixSID != nil || update.BaseAttributes.PrefixSID == nil {
		t.Errorf("unicast(%x) PrefixSID of the route, the UPDATE = %+v, %+v, want nil, unchanged",
			body, routes[0].BaseAttributes.PrefixSID, update.BaseAttributes.PrefixSID)
	}
}

// With no other TLV left, no empty prefix_sid object is published.
func TestPrefixSIDHoldingOnlyBadTLVLengthsIsOmitted(t *testing.T) {
	shortLabelIndex := []byte{0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0}
	shortSRGB := []byte{0x03, 0x00, 0x01, 0}
	tests := []struct {
		name string
		psid []byte
	}{
		{"a Label-Index of length six", shortLabelIndex},
		{"an Originator SRGB of length one", shortSRGB},
		{"a bad Label-Index beside a bad Originator SRGB", slices.Concat(shortLabelIndex, shortSRGB)},
	}
	for _, tt := range tests {
		t.Run(tt.name+" publishes no prefix_sid", func(t *testing.T) {
			check := func(family, action string, payloads [][]byte) {
				t.Helper()
				for _, payload := range payloads {
					got := decodeSRv6Route(t, payload)
					if got.Action != action || got.PrefixSID != nil || got.BaseAttrs["prefix_sid"] != nil {
						t.Errorf("producingWorker(%x) %s action, prefix_sid, base_attrs.prefix_sid = %q, %v, %v, want %q, none, none",
							tt.psid, family, got.Action, got.PrefixSID, got.BaseAttrs["prefix_sid"], action)
					}
				}
			}
			attr := benchPathAttr(benchOptionalTra, 40, tt.psid)
			check("VPNv4", "add", srv6VPNPayloads(t, 1, tt.psid, false))
			check("VPNv4", "del", srv6VPNPayloads(t, 1, tt.psid, true))
			check("VPNv6", "add", srv6VPNPayloads(t, 2, tt.psid, false))
			check("unicast IPv4", "add", srv6Payloads(t, bmp.UnicastPrefixV4Msg, append(benchCommonAttrs(nil),
				benchMPReach(1, 1, benchV4NH, benchRepeat(2, benchV4Prefix)), attr)))
			check("labeled unicast IPv4", "add", srv6Payloads(t, bmp.UnicastPrefixV4Msg, append(benchCommonAttrs(nil),
				benchMPReach(1, 4, benchV4NH, benchRepeat(2, benchLUPrefix)), attr)))
		})
	}
}

// A MUP discovery route needs the SRv6 SID, which a bad Label-Index must not
// take away (RFC 8669 §3.1).
func TestBadLabelIndexLeavesMUPDiscoveryRoutesAnnounced(t *testing.T) {
	psid := slices.Concat([]byte{0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0}, mupPrefixSIDAttribute())
	for _, tt := range []struct {
		name string
		nlri []byte
	}{
		{"ISD", benchMUPISD(0)},
		{"DSD", slices.Concat([]byte{1, 0, 2, 12}, benchRD, []byte{10, 0, 0, 1})},
	} {
		t.Run(tt.name+" is published with its SRv6 SID", func(t *testing.T) {
			body := benchUpdate(append(benchCommonAttrs(nil), benchMPReach(1, 85, benchV4NH, tt.nlri),
				benchPathAttr(benchOptionalTra, 40, psid)), nil)
			msgs := srv6Publish(t, body)
			if len(msgs) != 1 {
				t.Fatalf("producingWorker(%x) published %d messages, want 1", body, len(msgs))
			}
			got := decodeSRv6Route(t, msgs[0].payload)
			if got.Action != "add" || got.PrefixSID["srv6_l3_service"] == nil || got.PrefixSID["label_index"] != nil {
				t.Errorf("producingWorker(%x) action, prefix_sid = %q, %v, want add with only the SRv6 L3 Service",
					body, got.Action, got.PrefixSID)
			}
		})
	}
}

// RFC 9252 §7: unrecognized types and values which only fail semantic validation
// are not malformed, and all but the first Service TLV of a type are ignored.
func TestSRv6ServiceContentThatIsNotMalformedStaysAnnounced(t *testing.T) {
	// structure returns an Information Sub-TLV with one SID Structure of values.
	structure := func(values ...byte) []byte {
		return srv6InfoSubTLV(slices.Concat(srv6InfoFixed(), []byte{0x01, 0x00, byte(len(values))}, values))
	}
	for _, service := range []struct {
		name string
		typ  byte
	}{{"L3", 5}, {"L2", 6}} {
		tlv := func(subTLVs []byte) []byte {
			v := srv6PrefixSIDValue(subTLVs)
			v[0] = service.typ
			return v
		}
		valid := tlv(srv6InfoSubTLV(srv6InfoFixed()))
		tests := []struct {
			name string
			psid []byte
		}{
			{"an empty attribute", []byte{}},
			{"a Service TLV of length one", tlv(nil)},
			{"an Information Sub-TLV of length 21", valid},
			{"an unknown Sub-TLV of length zero", tlv([]byte{0x09, 0x00, 0x00})},
			{"an unknown Sub-Sub-TLV of length zero", tlv(srv6InfoSubTLV(append(srv6InfoFixed(), 0x02, 0x00, 0x00)))},
			{"a SID Structure of length five", tlv(structure(40, 24, 16, 0, 16))},
			{"a SID Structure of length seven", tlv(structure(40, 24, 16, 0, 16, 64, 0))},
			{"a SID Structure whose lengths exceed 128 bits", tlv(structure(64, 64, 64, 64, 0, 0))},
			{"a transposition length over 20", tlv(structure(40, 24, 16, 0, 24, 40))},
			{"a transposition ending at the sum of the lengths", tlv(structure(40, 24, 16, 0, 16, 64))},
			{"a transposition offset without a transposition length", tlv(structure(40, 24, 16, 0, 0, 64))},
			{"a second Service TLV of length zero", append(slices.Clone(valid), service.typ, 0x00, 0x00)},
			{"a second Service TLV with a malformed Sub-TLV",
				append(slices.Clone(valid), tlv(srv6InfoSubTLV(nil))...)},
		}
		for _, tt := range tests {
			t.Run(tt.name+" with "+service.name+" stays announced", func(t *testing.T) {
				for _, payload := range srv6VPNPayloads(t, 1, tt.psid, false) {
					got := decodeSRv6Route(t, payload)
					if _, flagged := got.BaseAttrs["srv6_service_malformed"]; flagged || got.Action != "add" {
						t.Errorf("producingWorker(%x) action = %q, base_attrs = %v, want add without srv6_service_malformed",
							tt.psid, got.Action, got.BaseAttrs)
					}
					if got.PrefixSID == nil || got.PrefixSID["srv6_l2_service"] != nil {
						t.Errorf("producingWorker(%x) prefix_sid = %v, want one without L2 content", tt.psid, got.PrefixSID)
					}
				}
			})
		}
	}
}

// RFC 7606 §3(g): all but the first Prefix-SID attribute are discarded.
func TestOnlyTheFirstPrefixSIDAttributeCounts(t *testing.T) {
	second := srv6InfoFixed()
	second[16] = 2 // SID 2001:db8:1:1::2
	first := srv6PrefixSIDValue(srv6InfoSubTLV(srv6InfoFixed()))
	other := srv6PrefixSIDValue(srv6InfoSubTLV(second))
	bad := []byte{0x05, 0x00, 0x00}
	tests := []struct {
		name      string
		values    [][]byte
		action    string
		malformed any
		sid       any
	}{
		{"a valid attribute hides a later malformed one", [][]byte{first, bad}, "add", nil, "2001:db8:1:1::"},
		{"a malformed attribute is not replaced by a later valid one", [][]byte{bad, first}, "del", true, nil},
		{"the SID of the first valid attribute is published", [][]byte{first, other}, "add", nil, "2001:db8:1:1::"},
	}
	// sidOf returns the first SID of a published prefix_sid object.
	sidOf := func(prefixSID any) any {
		var sid struct {
			Service struct {
				SubTLVs map[string][]struct {
					SID string `json:"sid"`
				} `json:"sub_tlvs"`
			} `json:"srv6_l3_service"`
		}
		b, err := json.Marshal(prefixSID)
		if err != nil || json.Unmarshal(b, &sid) != nil || len(sid.Service.SubTLVs["1"]) == 0 {
			return nil
		}
		return sid.Service.SubTLVs["1"][0].SID
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := append(benchCommonAttrs(nil),
				benchMPReach(1, 128, benchVPNNH6, benchRepeat(2, benchVPNPrefix([]byte{0x00, 0x10, 0x01}))))
			for _, value := range tt.values {
				attrs = append(attrs, benchPathAttr(benchOptionalTra, 40, value))
			}
			for _, payload := range srv6Payloads(t, bmp.L3VPNV4Msg, attrs) {
				got := decodeSRv6Route(t, payload)
				if got.Action != tt.action || got.BaseAttrs["srv6_service_malformed"] != tt.malformed {
					t.Errorf("producingWorker(%x) action, srv6_service_malformed = %q, %v, want %q, %v",
						tt.values, got.Action, got.BaseAttrs["srv6_service_malformed"], tt.action, tt.malformed)
				}
				if route, base := sidOf(got.PrefixSID), sidOf(got.BaseAttrs["prefix_sid"]); route != tt.sid || base != tt.sid {
					t.Errorf("producingWorker(%x) SIDs = %v and %v, want %v", tt.values, route, base, tt.sid)
				}
			}
		})
	}
}

// RFC 6368 §5: a malformed embedded attribute makes the ATTR_SET malformed, which
// RFC 7606 §7.16 treats as a withdrawal. The Prefix-SID is malformed when it
// cannot be parsed (RFC 8669 §6) or holds a malformed SRv6 Service TLV (RFC 9252
// §7), not for a Label-Index or SRGB length ignored by this family (RFC 8669
// §3.1, §3.2).
func TestAttrSetWithMalformedPrefixSIDWithdrawsRoutes(t *testing.T) {
	prefixSID := func(value ...byte) []byte { return benchPathAttr(benchOptionalTra, 40, value) }
	var (
		valid           = prefixSID(srv6PrefixSIDValue(srv6InfoSubTLV(srv6InfoFixed()))...)
		empty           = prefixSID()
		shortStructure  = prefixSID(srv6PrefixSIDValue(srv6InfoSubTLV(append(srv6InfoFixed(), srv6ShortSIDStructure()...)))...)
		shortLabelIndex = []byte{0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0}
		service         = srv6PrefixSIDValue(srv6InfoSubTLV(srv6InfoFixed()))
		overrun         = prefixSID(0x09, 0x00, 0x04)
		badService      = prefixSID(0x05, 0x00, 0x00)
		nested          = benchPathAttr(benchOptionalTra, 128, []byte{0, 0, 0xfd, 0xea})
	)
	tests := []struct {
		name      string
		embedded  [][]byte
		malformed bool
		want      string // embedded prefix_sid, checked when set
	}{
		{name: "a valid Prefix-SID stays announced", embedded: [][]byte{valid}},
		{name: "an empty Prefix-SID stays announced", embedded: [][]byte{empty}},
		{name: "a SID Structure of the wrong length stays announced", embedded: [][]byte{shortStructure}},
		{name: "a Label-Index of length six stays announced",
			embedded: [][]byte{prefixSID(slices.Concat(shortLabelIndex, service)...)},
			want:     `{` + srv6ServiceJSON + `}`},
		{name: "an Originator SRGB of length one stays announced",
			embedded: [][]byte{prefixSID(0x03, 0x00, 0x01, 0)}, want: `null`},
		{name: "a later malformed Prefix-SID is ignored", embedded: [][]byte{valid, badService}},
		{name: "a malformed SRv6 Service TLV withdraws", embedded: [][]byte{badService}, malformed: true},
		{name: "a malformed SRv6 Service TLV after a Label-Index of length six withdraws",
			embedded: [][]byte{prefixSID(slices.Concat(shortLabelIndex, []byte{0x05, 0x00, 0x00})...)}, malformed: true},
		{name: "a TLV running past the end of the attribute withdraws", embedded: [][]byte{overrun}, malformed: true},
		{name: "a TLV running past the end after a Label-Index of length six withdraws",
			embedded: [][]byte{prefixSID(slices.Concat(shortLabelIndex, []byte{0x09, 0x00, 0x04})...)}, malformed: true},
		{name: "a later valid Prefix-SID does not replace a malformed one",
			embedded: [][]byte{overrun, valid}, malformed: true},
		{name: "a malformed Prefix-SID beside a nested ATTR_SET withdraws",
			embedded: [][]byte{nested, overrun}, malformed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Origin AS 65001 followed by the embedded attributes.
			attrSet := slices.Concat(append([][]byte{{0, 0, 0xfd, 0xe9}}, tt.embedded...)...)
			attrs := append(benchCommonAttrs(nil),
				benchMPReach(1, 128, benchVPNNH6, benchRepeat(2, benchVPNPrefix([]byte{0x00, 0x10, 0x01}))),
				benchPathAttr(benchOptionalTra, 128, attrSet))
			action := "add"
			if tt.malformed {
				action = "del"
			}
			for _, payload := range srv6Payloads(t, bmp.L3VPNV4Msg, attrs) {
				got := decodeSRv6Route(t, payload)
				_, flagged := got.BaseAttrs["attr_set_malformed"]
				_, serviceFlagged := got.BaseAttrs["srv6_service_malformed"]
				if got.Action != action || flagged != tt.malformed || serviceFlagged ||
					(got.BaseAttrs["attr_set"] == nil) != tt.malformed {
					t.Errorf("producingWorker(%x) action = %q, base_attrs = %v, want %q, attr_set_malformed %t",
						attrSet, got.Action, got.BaseAttrs, action, tt.malformed)
				}
				if tt.want == "" {
					continue
				}
				var want any
				if err := json.Unmarshal([]byte(tt.want), &want); err != nil {
					t.Fatalf("json.Unmarshal(%s) error = %v, want nil", tt.want, err)
				}
				set, _ := got.BaseAttrs["attr_set"].(map[string]any)
				embedded, _ := set["path_attributes"].(map[string]any)
				if !reflect.DeepEqual(embedded["prefix_sid"], want) {
					t.Errorf("producingWorker(%x) embedded prefix_sid = %v, want %v", attrSet, embedded["prefix_sid"], want)
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

	for i, payload := range srv6VPNPayloads(t, 1, psid, false) {
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
				for _, payload := range srv6VPNPayloads(t, 1, psid, withdraw) {
					got := decodeSRv6Route(t, payload)
					if _, flagged := got.BaseAttrs["srv6_service_malformed"]; flagged || got.Action != action {
						t.Errorf("producingWorker(%x) action = %q, base_attrs = %v, want %q without srv6_service_malformed",
							psid, got.Action, got.BaseAttrs, action)
					}
					if !reflect.DeepEqual(any(got.PrefixSID), want) {
						t.Errorf("producingWorker(%x) prefix_sid = %v, want %v", psid, got.PrefixSID, want)
					}
					if !reflect.DeepEqual(got.BaseAttrs["prefix_sid"], want) {
						t.Errorf("producingWorker(%x) base_attrs.prefix_sid = %v, want %v", psid, got.BaseAttrs["prefix_sid"], want)
					}
				}
			})
		}
	}
}
