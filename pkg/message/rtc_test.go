package message

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/rtc"
)

// RFC 4684 §4 includes the complete Origin AS followed by 0..64 RT bits.
func TestProcessMPUpdateRTCPrefixes(t *testing.T) {
	tests := []struct {
		name   string
		length byte
		raw    string
		prefix string
		target string
	}{
		{name: "default", length: 0},
		{name: "origin only", length: 32},
		{name: "one RT bit with padding", length: 33, raw: "ff", prefix: "80"},
		{name: "seven RT bits with padding", length: 39, raw: "ff", prefix: "fe"},
		{name: "one RT octet", length: 40, raw: "00", prefix: "00"},
		{name: "31 RT bits with padding", length: 63, raw: "0002fdff", prefix: "0002fdfe"},
		{name: "first partial RT", length: 64, raw: "0002fde8", prefix: "0002fde8"},
		{name: "second partial RT", length: 64, raw: "0002fde9", prefix: "0002fde9"},
		{name: "33 RT bits with padding", length: 65, raw: "0002fde8ff", prefix: "0002fde880"},
		{name: "63 RT bits with padding", length: 95, raw: "0002fde800000065", prefix: "0002fde800000064"},
		{name: "two octet AS", length: 96, raw: "0002fde800000064", prefix: "0002fde800000064", target: "65000:100"},
		{name: "encoding flag retained", length: 96, raw: "4002fde800000064", prefix: "4002fde800000064", target: "65000:100"},
		{name: "IPv4 administrator", length: 96, raw: "0102c00002010064", prefix: "0102c00002010064", target: "192.0.2.1:100"},
		{name: "four octet AS", length: 96, raw: "0202000100000064", prefix: "0202000100000064", target: "65536:100"},
	}
	for _, afi := range []byte{1, 2} {
		for _, withdraw := range []bool{false, true} {
			t.Run(string(rune('0'+afi))+map[bool]string{false: "/add", true: "/del"}[withdraw], func(t *testing.T) {
				var wire []byte
				for _, tt := range tests {
					wire = append(wire, tt.length)
					if tt.length >= 32 {
						wire = append(wire, 0, 0, 0xfd, 0xe8) // Origin AS 65000
					}
					raw, err := hex.DecodeString(tt.raw)
					if err != nil {
						t.Fatal(err)
					}
					wire = append(wire, raw...)
				}
				original := bytes.Clone(wire)
				nlri := decodeRTCMP(t, afi, withdraw, wire)
				publisher := &recordingPublisher{}
				p := &producer{publisher: publisher}
				op, action, topic := AddPrefix, "add", bmp.RTCV4Msg
				if withdraw {
					op, action = DelPrefix, "del"
				}
				if afi == 2 {
					topic = bmp.RTCV6Msg
				}
				p.processMPUpdate(nlri, op, minimalPeerHeader(), minimalUpdate())
				if len(publisher.msgs) != len(tests) {
					t.Fatalf("published %d messages, want %d", len(publisher.msgs), len(tests))
				}
				for i, tt := range tests {
					t.Run(tt.name, func(t *testing.T) {
						msg := publisher.msgs[i]
						var got RTCPrefix
						if err := json.Unmarshal(msg.payload, &got); err != nil {
							t.Fatal(err)
						}
						wantAS := uint32(65000)
						if tt.length == 0 {
							wantAS = 0
						}
						if msg.msgType != topic || got.Action != action || got.IsIPv4 != (afi == 1) || got.IsEOR || got.Length != tt.length || got.OriginAS != wantAS || got.RouteTargetPrefix != tt.prefix || got.RouteTarget != tt.target {
							t.Errorf("published type=%d prefix=%+v; want type=%d action=%s length=%d origin=%d raw=%q target=%q", msg.msgType, got, topic, action, tt.length, wantAS, tt.prefix, tt.target)
						}
						encoded, err := json.Marshal(&got)
						if err != nil {
							t.Fatal(err)
						}
						var roundtrip RTCPrefix
						if err := json.Unmarshal(encoded, &roundtrip); err != nil || !reflect.DeepEqual(got, roundtrip) {
							t.Fatalf("JSON round trip lost RTC fields: error=%v got=%+v", err, roundtrip)
						}
						if tt.prefix == "" && bytes.Contains(msg.payload, []byte(`"route_target_prefix"`)) {
							t.Error("empty RT prefix must be omitted for default and origin-only membership")
						}
					})
				}
				if bytes.Equal(publisher.msgs[6].payload, publisher.msgs[7].payload) {
					t.Error("different /64 memberships published identical JSON")
				}
				if !bytes.Equal(original, wire) {
					t.Error("producer changed wire input")
				}
			})
		}
	}
}

// decodeRTCMP uses the real MP parsers, including withdrawal framing and dispatch.
func decodeRTCMP(t *testing.T, afi byte, withdraw bool, wire []byte) bgp.MPNLRI {
	t.Helper()
	var nlri bgp.MPNLRI
	var err error
	if withdraw {
		nlri, err = bgp.UnmarshalMPUnReachNLRI(append([]byte{0, afi, 132}, wire...), map[int]bool{})
	} else {
		nextHop := []byte{192, 0, 2, 1}
		if afi == 2 {
			nextHop = []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		}
		data := append([]byte{0, afi, 132, byte(len(nextHop))}, nextHop...)
		data = append(data, 0) // Reserved
		nlri, err = bgp.UnmarshalMPReachNLRI(append(data, wire...), false, map[int]bool{})
	}
	if err != nil {
		t.Fatal(err)
	}
	return nlri
}

// cachedRTCNLRIs returns the same decoded storage to expose producer mutations.
type cachedRTCNLRIs struct {
	bgp.MPNLRI
	route *rtc.Route
}

func (n cachedRTCNLRIs) GetNLRIRTC() (*rtc.Route, error) { return n.route, nil }

func TestRTCPrefixPreservesDecodedInput(t *testing.T) {
	for _, length := range []byte{33, 63, 95} {
		wire := append([]byte{length, 0, 0, 0xfd, 0xe8}, bytes.Repeat([]byte{0xff}, int((length-32+7)/8))...)
		nlri := decodeRTCMP(t, 1, false, wire)
		route, err := nlri.GetNLRIRTC()
		if err != nil {
			t.Fatal(err)
		}
		before := bytes.Clone(route.NLRI[0].RouteTarget)
		p := &producer{}
		if _, err := p.rtc(cachedRTCNLRIs{MPNLRI: nlri, route: route}, AddPrefix, minimalPeerHeader(), minimalUpdate()); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, route.NLRI[0].RouteTarget) {
			t.Errorf("/%d changed shared decoded RT from %x to %x", length, before, route.NLRI[0].RouteTarget)
		}
	}
}

func TestRTCLegacyJSON(t *testing.T) {
	var got RTCPrefix
	if err := json.Unmarshal([]byte(`{"length":96,"origin_as":65000,"route_target":"65000:100","is_ipv4":true}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.RouteTarget != "65000:100" || got.RouteTargetPrefix != "" || got.Length != 96 || got.OriginAS != 65000 {
		t.Fatalf("legacy JSON changed meaning: %+v", got)
	}
}

func TestRTCToleratedShortOriginPrefix(t *testing.T) {
	// Existing parser tolerance for invalid /1..31 is outside this producer fix.
	for _, length := range []byte{1, 31} {
		wire := append([]byte{length}, make([]byte, (int(length)+7)/8)...)
		nlri := decodeRTCMP(t, 1, false, wire)
		p := &producer{}
		got, err := p.rtc(nlri, AddPrefix, minimalPeerHeader(), minimalUpdate())
		if err != nil || len(got) != 1 || got[0].RouteTargetPrefix != "" || got[0].Length != length {
			t.Fatalf("tolerated /%d unexpectedly changed: prefixes=%+v error=%v", length, got, err)
		}
	}
}
