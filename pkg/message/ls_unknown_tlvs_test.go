package message

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestPublishedLSUnknownBGPLSTLVs(t *testing.T) {
	isisLocal := benchTLV(256, slices.Concat(
		benchTLV(512, 0, 0, 0xfd, 0xe8),
		benchTLV(515, 0, 0, 0, 0, 0, 1),
	)...)
	ospfLocal := benchTLV(256, slices.Concat(
		benchTLV(512, 0, 0, 0xfd, 0xe8),
		benchTLV(515, 192, 0, 2, 1),
	)...)
	bgpLocal := benchTLV(256, slices.Concat(
		benchTLV(512, 0, 0, 0xfd, 0xe8),
		benchTLV(516, 192, 0, 2, 1),
	)...)
	bgpRemote := benchTLV(257, slices.Concat(
		benchTLV(512, 0, 0, 0xfd, 0xe9),
		benchTLV(516, 192, 0, 2, 2),
	)...)
	node := lsUnknownTLVTestNLRI(1, base.ISISL2, isisLocal)
	ospfNode := lsUnknownTLVTestNLRI(1, base.OSPFv2, ospfLocal)
	bgpLink := lsUnknownTLVTestNLRI(2, base.BGP, bgpLocal, bgpRemote, benchTLV(259, 198, 51, 100, 1))
	prefix := lsUnknownTLVTestNLRI(3, base.OSPFv2, ospfLocal, benchTLV(265, 24, 198, 51, 100))

	peerSID := []byte{0, 5, 0, 0, 0, 0, 0, 33}
	tests := []struct {
		name   string
		nlri   []byte
		attr   []byte
		topic  int
		fields map[string]string
		raw    string
	}{
		{
			name: "node preserves order and repeats with empty values",
			nlri: node,
			attr: slices.Concat(
				benchTLV(64512, 0, 0xab),
				benchTLV(1025, 0x80),
				benchTLV(1037, 0xc8),
				benchTLV(1027, 0x49, 0x00, 0x01),
				benchTLV(64512),
				benchTLV(1032, 0, 0, 0, 7),
				benchTLV(64512, 0, 0xab),
				benchTLV(1098, 'x'), // Modeled on links.
			),
			topic: bmp.LSNodeMsg,
			fields: map[string]string{
				"area_id":               `"49.0001"`,
				"opaque_node_attribute": `["80"]`,
			},
			raw: `[{"type":64512,"value_hex":"00ab"},{"type":1037,"value_hex":"c8"},{"type":64512,"value_hex":""},{"type":1032,"value_hex":"00000007"},{"type":64512,"value_hex":"00ab"},{"type":1098,"value_hex":"78"}]`,
		},
		{
			name: "node does not map an IS-IS area TLV on OSPF",
			nlri: ospfNode,
			attr: slices.Concat(
				benchTLV(1027, 0x49, 0x00, 0x01),
				benchTLV(1024), // Recognized type with a malformed value.
				benchTLV(1026, 'n'),
			),
			topic:  bmp.LSNodeMsg,
			fields: map[string]string{"name": `"n"`, "node_flags": ""},
			raw:    `[{"type":1027,"value_hex":"490001"}]`,
		},
		{
			name: "BGP link uses structured peer SIDs and recognizes fallback types",
			nlri: bgpLink,
			attr: slices.Concat(
				benchTLV(1101, peerSID...),
				benchTLV(1102, peerSID...),
				benchTLV(1103, peerSID...),
				benchTLV(1028, 192, 0, 2, 1),
				benchTLV(1029, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
				benchTLV(258, 0, 0, 0, 7, 0, 0, 0, 8), // Existing Link ID fallback.
				benchTLV(1100, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x3e, 0x80),
			),
			topic: bmp.LSLinkMsg,
			fields: map[string]string{
				"router_id":     `"192.0.2.1"`,
				"local_link_id": "7",
			},
			raw: `[{"type":1100,"value_hex":"20010000000000000001003e80"}]`,
		},
		{
			name: "inter-AS link keeps unsupported attributes separate from descriptors",
			nlri: messageInterASLinkElement(),
			attr: slices.Concat(
				benchTLV(1101, peerSID...),
				benchTLV(1102, peerSID...),
				benchTLV(1103, peerSID...),
				benchTLV(1097, 0x01),
				benchTLV(1107, 0xab),
				benchTLV(1108, 0xcd),
			),
			topic:  bmp.LSLinkMsg,
			fields: map[string]string{"is_inter_as": "true", "opaque_link_attribute": `["01"]`},
			raw:    `[{"type":1101,"value_hex":"0005000000000021"},{"type":1102,"value_hex":"0005000000000021"},{"type":1103,"value_hex":"0005000000000021"},{"type":1107,"value_hex":"ab"},{"type":1108,"value_hex":"cd"}]`,
		},
		{
			name: "prefix publishes forwarding address once and skips nested TLVs",
			nlri: prefix,
			attr: slices.Concat(
				benchTLV(1155, 0, 0, 0, 5),
				benchTLV(1156, 192, 0, 2, 7),
				benchTLV(64513, 0xca, 0xfe),
				benchTLV(1157, 0xee),
				benchTLV(1159, append([]byte{0, 0, 0, 1}, benchTLV(64512, 0xfe)...)...),
				benchTLV(1170, 0),
				benchTLV(1171, 192, 0, 2, 2),
				benchTLV(1174, 192, 0, 2, 3),
			),
			topic: bmp.LSPrefixMsg,
			fields: map[string]string{
				"prefix_metric":           "5",
				"ospf_fwd_addr":           `"192.0.2.7"`,
				"opaque_prefix_attribute": `["ee"]`,
			},
			raw: `[{"type":64513,"value_hex":"cafe"}]`,
		},
		{
			name:   "known-only attributes omit the field",
			nlri:   node,
			attr:   benchTLV(1025, 0x01),
			topic:  bmp.LSNodeMsg,
			fields: map[string]string{"opaque_node_attribute": `["01"]`},
		},
		{
			name:   "missing attribute omits the field",
			nlri:   prefix,
			topic:  bmp.LSPrefixMsg,
			fields: map[string]string{"prefix": `"198.51.100.0"`},
		},
		{
			name:   "malformed attribute framing publishes no partial TLVs",
			nlri:   bgpLink,
			attr:   append(benchTLV(64512, 0xff), 0xff), // Truncated header after one valid TLV.
			topic:  bmp.LSLinkMsg,
			fields: map[string]string{"local_link_ip": `"198.51.100.1"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := [][]byte{
				benchPathAttr(benchWellKnown, 1, []byte{0}),
				benchPathAttr(benchWellKnown, 2, []byte{2, 1, 0, 0, 0xfd, 0xe8}),
				benchMPReach(16388, 71, []byte{203, 0, 113, 1}, tt.nlri),
			}
			if tt.attr != nil {
				attrs = append(attrs, benchPathAttr(benchOptional, 29, tt.attr))
			}
			update, err := bgp.UnmarshalBGPUpdate(benchUpdate(attrs, nil))
			if err != nil {
				t.Fatalf("unmarshal BGP UPDATE: %v", err)
			}
			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			p.produceRouteMessage(bmp.Message{
				PeerHeader: makePeerHeader(t, bmp.PeerType0, 0),
				Payload:    &bmp.RouteMonitor{Update: update},
			})
			if len(publisher.msgs) != 1 {
				t.Fatalf("published %d events, want 1", len(publisher.msgs))
			}
			got := publisher.msgs[0]
			if got.msgType != tt.topic {
				t.Fatalf("message type = %d, want %d", got.msgType, tt.topic)
			}
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(got.payload, &payload); err != nil {
				t.Fatalf("unmarshal published event: %v", err)
			}
			if raw := string(payload["unknown_bgp_ls_tlvs"]); raw != tt.raw {
				t.Errorf("unknown_bgp_ls_tlvs = %q, want %q", raw, tt.raw)
			}
			for field, want := range tt.fields {
				if value := string(payload[field]); value != want {
					t.Errorf("%s = %q, want %q", field, value, want)
				}
			}
		})
	}
}

func lsUnknownTLVTestNLRI(typ uint16, protocol base.ProtoID, descriptors ...[]byte) []byte {
	header := []byte{byte(protocol), 0, 0, 0, 0, 0, 0, 0, 0}
	return benchTLV(typ, append(header, slices.Concat(descriptors...)...)...)
}
