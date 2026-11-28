package message

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// srv6Publish publishes the BGP UPDATE body update, received on a session which
// negotiated ADD-PATH for addPath, and returns the messages it produced.
func srv6Publish(t *testing.T, update []byte, addPath ...bgp.AFISAFI) []recordedMsg {
	t.Helper()
	modes := map[bgp.AFISAFI]uint8{}
	for _, family := range addPath {
		modes[family] = 3 // send and receive (RFC 7911 §4)
	}
	pub := &recordingPublisher{}
	p := NewProducer(pub, true).(*producer)
	ph := benchPeerHeader()
	addPathPeerUp(t, p, ph, addPathOpen(t, nil, modes), addPathOpen(t, nil, modes))
	pub.msgs = nil
	p.producingWorker(routeMonitor(t, ph, afiBenchCase{name: "srv6", update: update}))
	return pub.msgs
}

// RFC 9252 §7 applies treat-as-withdraw to every route of the UPDATE, whatever
// its address family. The withdrawal must identify the route the announcement
// published.
func TestMalformedSRv6ServiceTLVWithdrawsEveryAddressFamily(t *testing.T) {
	goodL3 := mupPrefixSIDAttribute()
	goodL2 := srv6PrefixSIDValue(srv6InfoSubTLV(srv6InfoFixed()))
	goodL2[0] = 6
	badL3 := []byte{0x05, 0x00, 0x00}
	badL2 := []byte{0x06, 0x00, 0x00}

	mpReach := func(afi uint16, safi byte, nextHop, nlri []byte, extra ...[]byte) [][]byte {
		return append(append(benchCommonAttrs(nil), benchMPReach(afi, safi, nextHop, nlri)), extra...)
	}
	pathID := func(id uint32, nlri []byte) []byte {
		return append(binary.BigEndian.AppendUint32(nil, id), nlri...)
	}
	vpnLabel := []byte{0x00, 0x10, 0x01}
	otherRD := benchVPNPrefix(vpnLabel)(0)
	otherRD[11] = 2 // RD 65001:2
	rd := func(head []byte, tail ...byte) []byte { return slices.Concat(head, benchRD, tail) }

	tests := []struct {
		name      string
		attrs     [][]byte
		nlri      []byte // legacy IPv4 NLRI
		withdrawn []byte // legacy IPv4 Withdrawn Routes
		addPath   []bgp.AFISAFI
		bad       []byte // attribute 40, badL3 when nil
		good      []byte // attribute 40, goodL3 when nil
		msgTypes  []int
		// BGP-LS messages carry no base_attrs.
		noBaseAttrs bool
	}{
		{name: "IPv4 unicast in MP_REACH_NLRI", attrs: mpReach(1, 1, benchV4NH, benchV4Prefix(0)),
			msgTypes: []int{bmp.UnicastPrefixV4Msg}},
		{name: "IPv6 unicast", attrs: mpReach(2, 1, benchV6NH, []byte{32, 0x20, 0x01, 0x0d, 0xb8}),
			msgTypes: []int{bmp.UnicastPrefixV6Msg}},
		{name: "legacy IPv4 NLRI with withdrawn routes", attrs: benchCommonAttrs(benchV4NH),
			nlri: benchV4Prefix(0), withdrawn: benchV4Prefix(1),
			msgTypes: []int{bmp.UnicastPrefixV4Msg, bmp.UnicastPrefixV4Msg}},
		{name: "legacy IPv4 NLRI beside IPv6 MP_REACH_NLRI",
			attrs: append(benchCommonAttrs(benchV4NH), benchMPReach(2, 1, benchV6NH, []byte{32, 0x20, 0x01, 0x0d, 0xb8})),
			nlri:  benchV4Prefix(0), msgTypes: []int{bmp.UnicastPrefixV6Msg, bmp.UnicastPrefixV4Msg}},
		{name: "unicast paths with distinct path identifiers",
			attrs:    mpReach(1, 1, benchV4NH, append(pathID(1, benchV4Prefix(0)), pathID(2, benchV4Prefix(0))...)),
			addPath:  []bgp.AFISAFI{{AFI: 1, SAFI: 1}},
			msgTypes: []int{bmp.UnicastPrefixV4Msg, bmp.UnicastPrefixV4Msg}},
		{name: "labeled unicast", attrs: mpReach(1, 4, benchV4NH, benchLUPrefix(0)),
			msgTypes: []int{bmp.UnicastPrefixV4Msg}},
		{name: "VPN routes with distinct route distinguishers",
			attrs:    mpReach(1, 128, benchVPNNH4, append(benchVPNPrefix(vpnLabel)(0), otherRD...)),
			msgTypes: []int{bmp.L3VPNV4Msg, bmp.L3VPNV4Msg}},
		{name: "VPN paths with distinct path identifiers",
			attrs: mpReach(1, 128, benchVPNNH4,
				append(pathID(1, benchVPNPrefix(vpnLabel)(0)), pathID(2, benchVPNPrefix(vpnLabel)(0))...)),
			addPath:  []bgp.AFISAFI{{AFI: 1, SAFI: 128}},
			msgTypes: []int{bmp.L3VPNV4Msg, bmp.L3VPNV4Msg}},
		{name: "EVPN MAC/IP Advertisement with an L3 Service TLV", attrs: mpReach(25, 70, benchV4NH, benchEVPNType2(0)),
			msgTypes: []int{bmp.EVPNMsg}},
		{name: "EVPN Inclusive Multicast with an L2 Service TLV",
			attrs: mpReach(25, 70, benchV4NH, rd([]byte{3, 17}, 0, 0, 0, 0, 32, 192, 0, 2, 1)),
			good:  goodL2, bad: badL2, msgTypes: []int{bmp.EVPNMsg}},
		{name: "VPLS", attrs: mpReach(25, 65, benchV4NH, rd([]byte{0, 17}, 0, 1, 0, 1, 0, 8, 1, 0, 1)),
			msgTypes: []int{bmp.VPLSMsg}},
		{name: "SR Policy", attrs: mpReach(1, 73, benchV4NH,
			[]byte{96, 0, 0, 0, 1, 0, 0, 0, 100, 10, 0, 0, 9}, benchSRPolicyTunnelEncap),
			msgTypes: []int{bmp.SRPolicyV4Msg}},
		{name: "FlowSpec", attrs: mpReach(1, 133, nil, benchFlowspec(0)), msgTypes: []int{bmp.FlowspecV4Msg}},
		{name: "multicast", attrs: mpReach(1, 2, benchV4NH, benchV4Prefix(0)), msgTypes: []int{bmp.MulticastV4Msg}},
		{name: "MCAST-VPN", attrs: mpReach(1, 5, benchV4NH, rd([]byte{1, 12}, 192, 0, 2, 1)),
			msgTypes: []int{bmp.MCASTVPNV4Msg}},
		{name: "MVPN", attrs: mpReach(1, 129, benchV4NH, rd([]byte{1, 12}, 192, 0, 2, 1)),
			msgTypes: []int{bmp.MVPNV4Msg}},
		{name: "Route Target Constraint",
			attrs:    mpReach(1, 132, benchV4NH, append([]byte{96, 0, 0, 0xfd, 0xe9}, benchRT(65001, 1)...)),
			msgTypes: []int{bmp.RTCV4Msg}},
		{name: "MUP Interwork Segment Discovery", attrs: mpReach(1, 85, benchV4NH, benchMUPISD(0)),
			msgTypes: []int{bmp.MUPV4Msg}},
		{name: "MUP Direct Segment Discovery",
			attrs:    mpReach(1, 85, benchV4NH, rd([]byte{1, 0, 2, 12}, 10, 0, 0, 1)),
			msgTypes: []int{bmp.MUPV4Msg}},
		{name: "MUP Type 1 Session Transformed",
			attrs: mpReach(1, 85, benchV4NH, rd([]byte{1, 0, 3, 27},
				24, 0xc0, 0x64, 0, 0, 0, 0, 100, 9, 32, 10, 0, 0, 1, 32, 10, 0, 0, 2)),
			msgTypes: []int{bmp.MUPV4Msg}},
		{name: "BGP-LS prefix", attrs: mpReach(16388, 71, benchV4NH, benchLSPrefix(0), benchLSPrefixAttr),
			msgTypes: []int{bmp.LSPrefixMsg}, noBaseAttrs: true},
		{name: "BGP-LS opaque NLRI", attrs: mpReach(16388, 71, benchV4NH, benchTLV(200, 1, 2, 3)),
			msgTypes: []int{bmp.LSOpaqueMsg}, noBaseAttrs: true},
	}
	for _, tt := range tests {
		t.Run(tt.name+" is withdrawn", func(t *testing.T) {
			publish := func(psid []byte) []recordedMsg {
				attrs := append(slices.Clone(tt.attrs), benchPathAttr(benchOptionalTra, 40, psid))
				// Replace the empty Withdrawn Routes field benchUpdate writes.
				update := binary.BigEndian.AppendUint16(nil, uint16(len(tt.withdrawn)))
				update = append(append(update, tt.withdrawn...), benchUpdate(attrs, tt.nlri)[2:]...)
				return srv6Publish(t, update, tt.addPath...)
			}
			good, bad := goodL3, badL3
			if tt.bad != nil {
				good, bad = tt.good, tt.bad
			}
			announced, got := publish(good), publish(bad)
			if len(announced) != len(tt.msgTypes) || len(got) != len(tt.msgTypes) {
				t.Fatalf("producingWorker() published %d messages and %d with attribute %x, want %d",
					len(announced), len(got), bad, len(tt.msgTypes))
			}
			// route decodes a payload and splits off the members the attribute changes.
			route := func(payload []byte) (fields map[string]any, action any, baseAttrs map[string]any) {
				if err := json.Unmarshal(payload, &fields); err != nil {
					t.Fatalf("json.Unmarshal(%s) error = %v, want nil", payload, err)
				}
				action = fields["action"]
				baseAttrs, _ = fields["base_attrs"].(map[string]any)
				delete(fields, "action")
				delete(fields, "base_attrs")
				delete(fields, "prefix_sid")
				return fields, action, baseAttrs
			}
			hashes := map[string]bool{}
			for i, msg := range got {
				if msg.msgType != tt.msgTypes[i] || msg.msgType != announced[i].msgType || msg.key != announced[i].key {
					t.Errorf("message %d type, key = %d, %q, want %d, %q",
						i, msg.msgType, msg.key, tt.msgTypes[i], announced[i].key)
				}
				fields, action, baseAttrs := route(msg.payload)
				wantFields, wantAction, _ := route(announced[i].payload)
				// The legacy Withdrawn Routes come first and are always withdrawals.
				if isWithdrawn := i == 0 && tt.withdrawn != nil; !isWithdrawn && wantAction != "add" {
					t.Errorf("message %d action with attribute %x = %v, want add", i, good, wantAction)
				}
				if action != "del" || fields["is_eor"] != nil {
					t.Errorf("message %d action, is_eor = %v, %v, want del, none", i, action, fields["is_eor"])
				}
				if !reflect.DeepEqual(fields, wantFields) {
					t.Errorf("message %d route = %v, want %v", i, fields, wantFields)
				}
				switch {
				case tt.noBaseAttrs:
					if baseAttrs != nil {
						t.Errorf("message %d base_attrs = %v, want none", i, baseAttrs)
					}
				case i == 0 && tt.withdrawn != nil:
					// Withdrawn Routes are published without path attributes.
				case baseAttrs["srv6_service_malformed"] != true || baseAttrs["prefix_sid"] != nil:
					t.Errorf("message %d base_attrs = %v, want srv6_service_malformed and no prefix_sid", i, baseAttrs)
				}
				if hash, ok := fields["hash"].(string); ok {
					if hashes[hash] {
						t.Errorf("message %d hash %q repeats an earlier route's", i, hash)
					}
					hashes[hash] = true
				}
			}
		})
	}
}

// RFC 4724 §2: an UPDATE carrying another attribute beside an empty
// MP_UNREACH_NLRI is not an End-of-RIB marker.
func TestEmptyMPUnreachWithMalformedSRv6ServiceTLVPublishesNothing(t *testing.T) {
	tests := []struct {
		name   string
		family []byte // AFI and SAFI
	}{
		{"unicast", []byte{0, 1, 1}},
		{"VPN", []byte{0, 1, 128}},
		{"EVPN", []byte{0, 25, 70}},
		{"MUP", []byte{0, 1, 85}},
	}
	for _, tt := range tests {
		t.Run("an empty "+tt.name+" withdrawal publishes nothing", func(t *testing.T) {
			update := benchUpdate([][]byte{
				benchPathAttr(benchOptional, bgp.MP_UNREACH_NLRI, tt.family),
				benchPathAttr(benchOptionalTra, 40, []byte{0x05, 0x00, 0x00}),
			}, nil)
			if got := srv6Publish(t, update); len(got) != 0 {
				t.Errorf("producingWorker(%x) published %d messages, first %s, want none", update, len(got), got[0].payload)
			}
		})
	}
}
