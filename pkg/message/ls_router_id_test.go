package message

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// buildBGPLSAttrMulti concatenates several TLV encodings (via
// buildBGPLSAttrWithOpaque) into a single BGP-LS Attribute (type 29) payload.
func buildBGPLSAttrMulti(tlvs ...struct {
	Type  uint16
	Value []byte
}) []byte {
	var b []byte
	for _, tlv := range tlvs {
		b = append(b, buildBGPLSAttrWithOpaque(tlv.Type, tlv.Value)...)
	}
	return b
}

func rtIDAttr(tlvs ...struct {
	Type  uint16
	Value []byte
}) *bgp.Update {
	attr29 := buildBGPLSAttrMulti(tlvs...)
	return &bgp.Update{
		PathAttributes: []bgp.PathAttribute{
			{AttributeType: 29, AttributeLength: uint16(len(attr29)), Attribute: attr29},
		},
	}
}

var (
	v4Local = struct {
		Type  uint16
		Value []byte
	}{1028, []byte{10, 0, 0, 1}}
	v6Local = struct {
		Type  uint16
		Value []byte
	}{1029, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	v4Remote = struct {
		Type  uint16
		Value []byte
	}{1030, []byte{192, 168, 1, 1}}
	v6Remote = struct {
		Type  uint16
		Value []byte
	}{1031, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}
)

// TestLSNode_RouterID_ByTLVPresence covers RFC 9552 §5.3.1.4. Both
// families have their own optional JSON field, and the legacy router_id
// still prefers IPv4 when both are present.
func TestLSNode_RouterID_ByTLVPresence(t *testing.T) {
	badV4, badV6 := v4Local, v6Local
	badV4.Value = []byte{10, 0, 0}
	badV6.Value = make([]byte, 17)
	tests := []struct {
		name   string
		attr   *bgp.Update
		legacy string
		ipv4   string
		ipv6   string
	}{
		{"ipv4-only TLV", rtIDAttr(v4Local), "10.0.0.1", "10.0.0.1", ""},
		{"ipv6-only TLV", rtIDAttr(v6Local), "2001:db8::1", "", "2001:db8::1"},
		{"both TLVs present, prefer IPv4", rtIDAttr(v4Local, v6Local), "10.0.0.1", "10.0.0.1", "2001:db8::1"},
		{"neither TLV present", rtIDAttr(), "", "", ""},
		{"no BGP-LS attribute", &bgp.Update{}, "", "", ""},
		{"wrong IPv4 length and valid IPv6", rtIDAttr(badV4, v6Local), "2001:db8::1", "", "2001:db8::1"},
		{"valid IPv4 and wrong IPv6 length", rtIDAttr(v4Local, badV6), "10.0.0.1", "10.0.0.1", ""},
		{"both wrong lengths", rtIDAttr(badV4, badV6), "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &producer{}
			msg, err := p.lsNode(testLSNode(base.ISISL1), "", 0, newPeerHeader(), tt.attr)
			if err != nil {
				t.Fatalf("lsNode() error: %v", err)
			}
			payload, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("marshal LS Node JSON: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(payload, &fields); err != nil {
				t.Fatalf("unmarshal LS Node JSON: %v", err)
			}
			for name, want := range map[string]string{
				"router_id":            tt.legacy,
				"local_ipv4_router_id": tt.ipv4,
				"local_ipv6_router_id": tt.ipv6,
			} {
				value, present := fields[name]
				if want == "" {
					if present {
						t.Errorf("%s = %s, want field omitted", name, value)
					}
					continue
				}
				var got string
				if err := json.Unmarshal(value, &got); err != nil || got != want {
					t.Errorf("%s = %s, want %q (error: %v)", name, value, want, err)
				}
			}
		})
	}
}

// TestLSLink_RouterID_ByTLVPresence covers RFC 9552 Section 5.3.2.1: TLVs
// 1028/1030 (IPv4) and 1029/1031 (IPv6) local/remote router-IDs are chosen by
// TLV presence, not by the BMP peer's V-flag.
func TestLSLink_RouterID_ByTLVPresence(t *testing.T) {
	tests := []struct {
		name       string
		attr       *bgp.Update
		wantLocal  string
		wantRemote string
	}{
		{"ipv4-only TLVs", rtIDAttr(v4Local, v4Remote), "10.0.0.1", "192.168.1.1"},
		{"ipv6-only TLVs", rtIDAttr(v6Local, v6Remote), "2001:db8::1", "2001:db8::2"},
		{"both present, prefer IPv4", rtIDAttr(v4Local, v6Local, v4Remote, v6Remote), "10.0.0.1", "192.168.1.1"},
		{"ipv4 local, ipv6-only remote", rtIDAttr(v4Local, v6Remote), "10.0.0.1", "2001:db8::2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := &base.LinkNLRI{
				ProtocolID: base.ISISL1,
				LocalNode:  &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
				RemoteNode: &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
				Link:       &base.LinkDescriptor{LinkTLV: map[uint16]base.TLV{}},
			}
			p := &producer{}
			msg, err := p.lsLink(link, "", 0, newPeerHeader(), tt.attr, false)
			if err != nil {
				t.Fatalf("lsLink() error: %v", err)
			}
			if msg.RouterID != tt.wantLocal {
				t.Errorf("RouterID = %q, want %q", msg.RouterID, tt.wantLocal)
			}
			if msg.RemoteRouterID != tt.wantRemote {
				t.Errorf("RemoteRouterID = %q, want %q", msg.RemoteRouterID, tt.wantRemote)
			}
		})
	}
}

// linkRouterIDs lists the router-ID values expected in published ls_link JSON.
// An empty value means the field must be omitted.
type linkRouterIDs struct {
	local, remote          string
	localIPv4, localIPv6   string
	remoteIPv4, remoteIPv6 string
}

// assertPublishedLinkRouterIDs checks the single published ls_link message.
func assertPublishedLinkRouterIDs(t *testing.T, rec *recordingPublisher, wantAction string, want linkRouterIDs) {
	t.Helper()
	if len(rec.msgs) != 1 || rec.msgs[0].msgType != bmp.LSLinkMsg {
		t.Fatalf("published messages = %+v, want one ls_link", rec.msgs)
	}
	var fields map[string]any
	if err := json.Unmarshal(rec.msgs[0].payload, &fields); err != nil {
		t.Fatalf("unmarshal ls_link JSON: %v", err)
	}
	if fields["action"] != wantAction {
		t.Errorf("action = %v, want %q", fields["action"], wantAction)
	}
	for name, value := range map[string]string{
		"router_id":             want.local,
		"remote_router_id":      want.remote,
		"local_ipv4_router_id":  want.localIPv4,
		"local_ipv6_router_id":  want.localIPv6,
		"remote_ipv4_router_id": want.remoteIPv4,
		"remote_ipv6_router_id": want.remoteIPv6,
	} {
		got, present := fields[name]
		if value == "" {
			if present {
				t.Errorf("%s = %v, want field omitted", name, got)
			}
			continue
		}
		if got != value {
			t.Errorf("%s = %v, want %q", name, got, value)
		}
	}
}

// linkRouterIDTLVs builds TLVs 1028-1031 with the given value lengths.
func linkRouterIDTLVs(ipv4Length, ipv6Length int) []lsSPFTLV {
	resize := func(value []byte, length int) []byte {
		return append(value, make([]byte, 17)...)[:length]
	}
	return []lsSPFTLV{
		{1028, resize([]byte{10, 0, 0, 1}, ipv4Length)},
		{1029, resize(net.ParseIP("2001:db8::1"), ipv6Length)},
		{1030, resize([]byte{192, 168, 1, 1}, ipv4Length)},
		{1031, resize(net.ParseIP("2001:db8::2"), ipv6Length)},
	}
}

var dualStackLinkRouterIDs = linkRouterIDs{
	local: "10.0.0.1", remote: "192.168.1.1",
	localIPv4: "10.0.0.1", localIPv6: "2001:db8::1",
	remoteIPv4: "192.168.1.1", remoteIPv6: "2001:db8::2",
}

// TestProcessMPUpdateLSLinkRouterIDsPerFamily decodes SAFI 71 Link NLRIs and
// BGP-LS Attribute TLVs 1028-1031 from wire bytes. RFC 9552 Section 5.3.2.1:
// "All auxiliary Router-IDs of both the local and the remote node MUST be
// included in the link attribute of each Link NLRI."
func TestProcessMPUpdateLSLinkRouterIDsPerFamily(t *testing.T) {
	dual := linkRouterIDTLVs(4, 16)
	ipv4Only := linkRouterIDs{
		local: "10.0.0.1", remote: "192.168.1.1",
		localIPv4: "10.0.0.1", remoteIPv4: "192.168.1.1",
	}
	ipv6Only := linkRouterIDs{
		local: "2001:db8::1", remote: "2001:db8::2",
		localIPv6: "2001:db8::1", remoteIPv6: "2001:db8::2",
	}
	tests := []struct {
		name string
		tlvs []lsSPFTLV
		want linkRouterIDs
	}{
		{"publishes both families of a dual-stack link", dual, dualStackLinkRouterIDs},
		{"publishes only IPv4 fields for an IPv4 link", []lsSPFTLV{dual[0], dual[2]}, ipv4Only},
		{"publishes only IPv6 fields for an IPv6 link", []lsSPFTLV{dual[1], dual[3]}, ipv6Only},
		{"fills each side from its own TLV", []lsSPFTLV{dual[0], dual[3]}, linkRouterIDs{
			local: "10.0.0.1", remote: "2001:db8::2",
			localIPv4: "10.0.0.1", remoteIPv6: "2001:db8::2",
		}},
		{"omits all fields without router-ID TLVs", []lsSPFTLV{testLSSequence()}, linkRouterIDs{}},
		{"omits all fields without a BGP-LS Attribute", nil, linkRouterIDs{}},
		// The wrong-length cases describe current handling. RFC 9552 Section
		// 8.2.2 asks for the whole BGP-LS Attribute to be discarded instead.
		{"omits empty values", linkRouterIDTLVs(0, 0), linkRouterIDs{}},
		{"omits values one octet short", linkRouterIDTLVs(3, 15), linkRouterIDs{}},
		{"omits values one octet long", linkRouterIDTLVs(5, 17), linkRouterIDs{}},
		{"omits values that have the other family's length", linkRouterIDTLVs(16, 4), linkRouterIDs{}},
		{"keeps IPv6 when the IPv4 length is wrong", linkRouterIDTLVs(5, 16), ipv6Only},
		{"keeps IPv4 when the IPv6 length is wrong", linkRouterIDTLVs(4, 17), ipv4Only},
	}
	for _, tt := range tests {
		for _, withdraw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, withdraw=%t", tt.name, withdraw), func(t *testing.T) {
				var nlri bgp.MPNLRI
				var err error
				operation, action := AddPrefix, "add"
				if withdraw {
					nlri, err = bgp.UnmarshalMPUnReachNLRI(append([]byte{0x40, 0x04, 71}, testLSLinkNLRI80()...), map[int]bool{})
					operation, action = DelPrefix, "del"
				} else {
					nlri, err = bgp.UnmarshalMPReachNLRI(append([]byte{0x40, 0x04, 71, 4, 192, 0, 2, 2, 0}, testLSLinkNLRI80()...), false, map[int]bool{})
				}
				if err != nil {
					t.Fatalf("unmarshal MP NLRI: %v", err)
				}
				update := &bgp.Update{}
				if tt.tlvs != nil {
					update = testLSUpdate(tt.tlvs...)
				}
				rec := &recordingPublisher{}
				p := &producer{publisher: rec}

				p.processMPUpdate(nlri, operation, minimalPeerHeader(), update)

				assertPublishedLinkRouterIDs(t, rec, action, tt.want)
			})
		}
	}
}

// TestProcessMPUpdateLSLinkRouterIDsOtherPaths checks that BGP-LS-VPN, BGP-LS-SPF
// and Inter-AS ls_link messages carry the same router-ID fields.
func TestProcessMPUpdateLSLinkRouterIDsOtherPaths(t *testing.T) {
	linkBody := testLSLinkNLRI80()[4:]
	tests := []struct {
		name string
		safi byte
		nlri []byte
	}{
		{"BGP-LS-VPN link", 72, testLSVPNEntry(2, testRD, linkBody)},
		{"BGP-LS-SPF link", 80, testLSLinkNLRI80()},
		{"Inter-AS link", 71, messageInterASLinkElement()},
	}
	// RFC 9815 requires the sequence number and IGP metric for an SPF link add.
	tlvs := append(linkRouterIDTLVs(4, 16), testLSSequence(), lsSPFTLV{bgpLSIGPMetricTLV, []byte{0, 0, 0, 10}})
	for _, tt := range tests {
		for _, withdraw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s publishes both families, withdraw=%t", tt.name, withdraw), func(t *testing.T) {
				var nlri bgp.MPNLRI
				var err error
				operation, action := AddPrefix, "add"
				if withdraw {
					nlri, err = bgp.UnmarshalMPUnReachNLRI(append([]byte{0x40, 0x04, tt.safi}, tt.nlri...), map[int]bool{})
					operation, action = DelPrefix, "del"
				} else {
					// SAFI 72 prefixes the next hop with an 8-octet zero RD.
					header := []byte{0x40, 0x04, tt.safi, 4, 192, 0, 2, 2, 0}
					if tt.safi == 72 {
						header = testLSVPNMPReachHeader[:]
					}
					nlri, err = bgp.UnmarshalMPReachNLRI(append(append([]byte{}, header...), tt.nlri...), false, map[int]bool{})
				}
				if err != nil {
					t.Fatalf("unmarshal MP NLRI: %v", err)
				}
				rec := &recordingPublisher{}
				p := &producer{publisher: rec}

				p.processMPUpdate(nlri, operation, minimalPeerHeader(), testLSUpdate(tlvs...))

				assertPublishedLinkRouterIDs(t, rec, action, dualStackLinkRouterIDs)
			})
		}
	}
}

// TestLSPrefix_RouterID_FallsBackToIPv6 covers the router-ID selection in
// pkg/message/ls-prefix.go: the router-ID TLV is chosen by which TLV
// (1028/1029) is present, not by the prefix NLRI type (ipv4 argument).
func TestLSPrefix_RouterID_FallsBackToIPv6(t *testing.T) {
	tests := []struct {
		name string
		ipv4 bool // prefix NLRI type - must not affect the router-ID result
		attr *bgp.Update
		want string
	}{
		{"ipv4 prefix, ipv6-only TLV", true, rtIDAttr(v6Local), "2001:db8::1"},
		{"ipv6 prefix, ipv4-only TLV", false, rtIDAttr(v4Local), "10.0.0.1"},
		{"ipv6 prefix, both present, prefer IPv4", false, rtIDAttr(v4Local, v6Local), "10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixDesc := &base.PrefixDescriptor{
				PrefixTLV: map[uint16]base.TLV{
					265: {Type: 265, Length: 4, Value: []byte{0x18, 0x0a, 0x00, 0x00}},
				},
			}
			prfx := &base.PrefixNLRI{
				ProtocolID: base.ISISL1,
				LocalNode:  &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
				Prefix:     prefixDesc,
				IsIPv4:     tt.ipv4,
			}
			p := &producer{}
			msg, err := p.lsPrefix(prfx, "", 0, newPeerHeader(), tt.attr, tt.ipv4)
			if err != nil {
				t.Fatalf("lsPrefix() error: %v", err)
			}
			if msg.RouterID != tt.want {
				t.Errorf("RouterID = %q, want %q", msg.RouterID, tt.want)
			}
		})
	}
}

// TestProcessMPUpdate_LS71_RouterIDWire decodes a BGP-LS (AFI 16388, SAFI 71)
// MP_REACH_NLRI with a Node and a Link NLRI from an IPv4 BMP peer, where the
// BGP-LS Attribute carries only IPv6 router-IDs (TLV 1029/1031). The IPv6
// router-IDs must still be emitted (RFC 9552 Section 5.3.1.4).
func TestProcessMPUpdate_LS71_RouterIDWire(t *testing.T) {
	localND := []byte{
		0x01, 0x00, 0x00, 0x0a, // Local Node Descriptors, length 10
		0x02, 0x03, 0x00, 0x06, 0, 0, 0, 0, 0, 1, // IGP Router-ID TLV 515
	}
	remoteND := []byte{
		0x01, 0x01, 0x00, 0x0a, // Remote Node Descriptors, length 10
		0x02, 0x03, 0x00, 0x06, 0, 0, 0, 0, 0, 2,
	}
	hdr := []byte{byte(base.ISISL2), 0, 0, 0, 0, 0, 0, 0, 0} // Protocol-ID + Identifier
	node := append(append([]byte{}, hdr...), localND...)
	link := append(append(append([]byte{}, hdr...), localND...), remoteND...)
	lsNLRI := func(typ byte, body []byte) []byte {
		return append([]byte{0, typ, 0, byte(len(body))}, body...)
	}
	attr := []byte{0x40, 0x04, 71, 4, 192, 0, 2, 1, 0} // AFI 16388, SAFI 71, NH 192.0.2.1
	attr = append(attr, lsNLRI(1, node)...)
	attr = append(attr, lsNLRI(2, link)...)

	nlri, err := bgp.UnmarshalMPReachNLRI(attr, false, map[int]bool{})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI() error: %v", err)
	}
	rec := &recordingPublisher{}
	p := &producer{publisher: rec}
	p.processMPUpdate(nlri, 0, makePeerHeader(t, bmp.PeerType0, 0x00), rtIDAttr(v6Local, v6Remote))

	var gotNode, gotLink bool
	for _, m := range rec.msgs {
		var out struct {
			RouterID          string `json:"router_id"`
			RemoteRouterID    string `json:"remote_router_id"`
			LocalIPv6RouterID string `json:"local_ipv6_router_id"`
		}
		if err := json.Unmarshal(m.payload, &out); err != nil {
			t.Fatalf("json.Unmarshal() error: %v", err)
		}
		switch m.msgType {
		case bmp.LSNodeMsg:
			gotNode = true
			if out.RouterID != "2001:db8::1" {
				t.Errorf("ls_node router_id = %q, want %q", out.RouterID, "2001:db8::1")
			}
			if out.LocalIPv6RouterID != "2001:db8::1" {
				t.Errorf("ls_node local_ipv6_router_id = %q, want %q", out.LocalIPv6RouterID, "2001:db8::1")
			}
		case bmp.LSLinkMsg:
			gotLink = true
			if out.RouterID != "2001:db8::1" || out.RemoteRouterID != "2001:db8::2" {
				t.Errorf("ls_link router_id/remote_router_id = %q/%q, want %q/%q",
					out.RouterID, out.RemoteRouterID, "2001:db8::1", "2001:db8::2")
			}
		}
	}
	if !gotNode || !gotLink {
		t.Fatalf("published ls_node=%v ls_link=%v, want both", gotNode, gotLink)
	}
}
