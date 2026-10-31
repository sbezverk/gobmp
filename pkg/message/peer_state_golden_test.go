package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// testRT is the rt=100:1 Route Target extended community.
var testRT = []byte{0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01}

// mpTestAttr returns an MP_REACH_NLRI (code 14) or MP_UNREACH_NLRI (code 15)
// path attribute for AFI afi SAFI safi. The next hop is only used for 14.
func mpTestAttr(code byte, afi byte, safi byte, nh []byte, nlri []byte) []byte {
	if code == 0x0e {
		return dPathReach(uint16(afi), safi, nh, nlri)
	}
	return dPathUnreach(uint16(afi), safi, nlri)
}

// testUpdate builds a BGP UPDATE (RFC 4271 §4.3) whose path attributes are
// ORIGIN, AS_PATH, EXTENDED COMMUNITIES (when extComms is not empty) and attr.
func testUpdate(t *testing.T, attr []byte, extComms ...[]byte) *bgp.Update {
	t.Helper()
	var ec []byte
	for _, c := range extComms {
		ec = append(ec, c...)
	}
	attrs := []byte{
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe8, // AS_PATH AS_SEQUENCE 65000
	}
	if len(ec) != 0 {
		attrs = append(attrs, 0xc0, 0x10, byte(len(ec)))
		attrs = append(attrs, ec...)
	}
	attrs = append(attrs, attr...)
	b := append([]byte{0x00, 0x00, byte(len(attrs) >> 8), byte(len(attrs))}, attrs...)
	update, err := bgp.UnmarshalBGPUpdateWithAS4Hint(b, true)
	if err != nil {
		t.Fatalf("UnmarshalBGPUpdateWithAS4Hint() error: %v", err)
	}
	return update
}

// plainTestUpdate builds a BGP UPDATE (RFC 4271 §4.3) with the Withdrawn
// Routes and NLRI fields given and the path attributes ORIGIN, AS_PATH and,
// when nlri is not empty, NEXT_HOP 192.0.2.1.
func plainTestUpdate(t *testing.T, withdrawn, nlri []byte) *bgp.Update {
	t.Helper()
	attrs := []byte{
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe8, // AS_PATH AS_SEQUENCE 65000
	}
	if len(nlri) != 0 {
		attrs = append(attrs, 0x40, 0x03, 0x04, 192, 0, 2, 1) // NEXT_HOP
	}
	b := []byte{byte(len(withdrawn) >> 8), byte(len(withdrawn))}
	b = append(b, withdrawn...)
	b = append(b, byte(len(attrs)>>8), byte(len(attrs)))
	b = append(b, attrs...)
	b = append(b, nlri...)
	update, err := bgp.UnmarshalBGPUpdateWithAS4Hint(b, true)
	if err != nil {
		t.Fatalf("UnmarshalBGPUpdateWithAS4Hint() error: %v", err)
	}
	return update
}

// publishWithPeerUp sends a Peer Up whose OPENs both carry ADD-PATH mode 3
// (send and receive) for the families in addPath when it is not nil, then a
// Route Monitoring of update, and returns the messages published for it.
func publishWithPeerUp(t *testing.T, ph *bmp.PerPeerHeader, addPath [][2]byte, update *bgp.Update) []recordedMsg {
	t.Helper()
	pub := &recordingPublisher{}
	p := NewProducer(pub, false).(*producer)
	if addPath != nil {
		modes := map[bgp.AFISAFI]uint8{}
		for _, as := range addPath {
			modes[bgp.AFISAFI{AFI: uint16(as[0]), SAFI: as[1]}] = 3
		}
		open := addPathOpen(t, nil, modes)
		addPathPeerUp(t, p, ph, open, open)
	}
	n := len(pub.msgs)
	p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: update}})
	return pub.msgs[n:]
}

// TestPathIDDecodersPublishedJSONGolden pins the JSON published for valid
// SAFI 1, plain NLRI field, multicast and L3VPN input, with and without
// ADD-PATH negotiated in both directions, so per-session ADD-PATH state
// changes are shown not to change consumer output for valid input.
func TestPathIDDecodersPublishedJSONGolden(t *testing.T) {
	v4NH := []byte{192, 0, 2, 1}
	v6NH := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	pathID := []byte{0x00, 0x00, 0x00, 0x07}
	cat := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	v4Prefix := []byte{0x18, 0x0a, 0x01, 0x02}                                      // 10.1.2.0/24
	v6Prefix := []byte{0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}        // 2001:db8:1::/64
	vpnV4 := []byte{0x70, 0x05, 0xdc, 0x31, 0, 0, 0, 0x64, 0, 0, 0, 0x01, 10, 1, 2} // label 24003, RD 100:1, 10.1.2.0/24
	vpnV4Withdraw := []byte{0x70, 0x80, 0x00, 0x00, 0, 0, 0, 0x64, 0, 0, 0, 0x01, 10, 1, 2}
	tests := []struct {
		name     string
		addPath  [][2]byte // AFI/SAFI with ADD-PATH 3 in both OPENs; nil for no Peer Up
		update   func(t *testing.T) *bgp.Update
		wantType int
		want     []string
	}{
		{
			name:     "SAFI 1 IPv4 announce",
			update:   func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0e, 1, 1, v4NH, v4Prefix)) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"bb239fe17b30ba78ab7d6ac4eec7f5e1","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"70c1b182424e4aab11fe503d6469421e","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":1,"safi":1}`,
			},
		},
		{
			name:    "SAFI 1 IPv4 announce, ADD-PATH",
			addPath: [][2]byte{{1, 1}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 1, 1, v4NH, cat(pathID, v4Prefix)))
			},
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"5ff42bcb7b8d20b1384921ad9a9ae305","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"685b67d472a35e9c60ca2f5b4c83010a","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"path_id":7,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":1,"safi":1}`,
			},
		},
		{
			name:    "SAFI 1 IPv4 withdraw, ADD-PATH",
			addPath: [][2]byte{{1, 1}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0f, 1, 1, nil, cat(pathID, v4Prefix)))
			},
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"del","hash":"5ff42bcb7b8d20b1384921ad9a9ae305","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"50f7d6f03a641d8e0e965053c734457f","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"is_nexthop_ipv4":true,"path_id":7,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":1,"safi":1}`,
			},
		},
		{
			name:     "SAFI 1 IPv6 announce",
			update:   func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0e, 2, 1, v6NH, v6Prefix)) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"ba1c3c731087ea4b4a5461ed2eed9c19","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"5266280949e906ade580d100a53f3f40","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"2001:db8:1::","prefix_len":64,"is_ipv4":false,"origin_as":65000,"nexthop":"2001:db8::1","is_nexthop_ipv4":false,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":2,"safi":1}`,
			},
		},
		{
			name:    "SAFI 1 IPv6 announce, ADD-PATH",
			addPath: [][2]byte{{2, 1}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 2, 1, v6NH, cat(pathID, v6Prefix)))
			},
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"dd15844d205beab74bb17569effa7b9f","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"7e59ee3af18bc292e78b978fcf37e18e","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"2001:db8:1::","prefix_len":64,"is_ipv4":false,"origin_as":65000,"nexthop":"2001:db8::1","is_nexthop_ipv4":false,"path_id":7,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":2,"safi":1}`,
			},
		},
		{
			name:     "SAFI 1 IPv6 withdraw",
			update:   func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0f, 2, 1, nil, v6Prefix)) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"del","hash":"ba1c3c731087ea4b4a5461ed2eed9c19","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"4ee7658cbf43b7c9b63b26a24b333327","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"2001:db8:1::","prefix_len":64,"is_ipv4":false,"origin_as":65000,"is_nexthop_ipv4":false,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":2,"safi":1}`,
			},
		},
		{
			name:     "NLRI field announce",
			update:   func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, v4Prefix) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"bb239fe17b30ba78ab7d6ac4eec7f5e1","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"8cb57e2a9c62e1d3c1ba4fec098235b0","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"nexthop":"192.0.2.1","is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":1,"safi":1}`,
			},
		},
		{
			name:     "NLRI field announce, ADD-PATH",
			addPath:  [][2]byte{{1, 1}},
			update:   func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, cat(pathID, v4Prefix)) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"5ff42bcb7b8d20b1384921ad9a9ae305","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"8cb57e2a9c62e1d3c1ba4fec098235b0","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"nexthop":"192.0.2.1","is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"path_id":7,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":1,"safi":1}`,
			},
		},
		{
			// With path attributes and a withdrawal it is not an End-of-RIB
			// (RFC 4724 §2).
			name:     "Withdrawn Routes field, ADD-PATH",
			addPath:  [][2]byte{{1, 1}},
			update:   func(t *testing.T) *bgp.Update { return plainTestUpdate(t, cat(pathID, v4Prefix), nil) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"del","hash":"5ff42bcb7b8d20b1384921ad9a9ae305","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"72cfb7866f58de0f7bc8aa588bd5a180","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"is_nexthop_ipv4":true,"path_id":7,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":1,"safi":1}`,
			},
		},
		{
			name:     "multicast IPv4 announce",
			update:   func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0e, 1, 2, v4NH, v4Prefix)) },
			wantType: bmp.MulticastV4Msg,
			want: []string{
				`{"action":"add","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"85f498c7ad0f70ab0d74ad3e59575847","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
			},
		},
		{
			name:    "multicast IPv6 announce, ADD-PATH",
			addPath: [][2]byte{{2, 2}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 2, 2, v6NH, cat(pathID, v6Prefix)))
			},
			wantType: bmp.MulticastV6Msg,
			want: []string{
				`{"action":"add","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"e6acec950dc0ce4f610285a3bc28944c","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"2001:db8:1::","prefix_len":64,"is_ipv4":false,"origin_as":65000,"nexthop":"2001:db8::1","is_nexthop_ipv4":false,"path_id":7,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
			},
		},
		{
			name:    "VPNv4 announce, ADD-PATH",
			addPath: [][2]byte{{1, 128}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 1, 128, v4NH, cat(pathID, vpnV4)), testRT)
			},
			wantType: bmp.L3VPNMsg,
			want: []string{
				`{"action":"add","hash":"08e8c17a52a7ce1618f2dbafe9cf6d8f","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"7e5a33b159a7dcc50c487cec2f0448e2","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false,"ext_community_list":["rt=100:1"]},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"path_id":7,"labels":[24003],"vpn_rd":"100:1","vpn_rd_type":0,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":1,"safi":128}`,
			},
		},
		{
			name:    "VPNv4 withdraw, ADD-PATH",
			addPath: [][2]byte{{1, 128}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0f, 1, 128, nil, cat(pathID, vpnV4Withdraw)))
			},
			wantType: bmp.L3VPNMsg,
			want: []string{
				`{"action":"del","hash":"08e8c17a52a7ce1618f2dbafe9cf6d8f","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"d35d9688814a937b06ad2e33c16b54d4","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"is_nexthop_ipv4":true,"path_id":7,"vpn_rd":"100:1","vpn_rd_type":0,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false,"afi":1,"safi":128}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := publishWithPeerUp(t, minimalPeerHeader(), tt.addPath, tt.update(t))
			if len(msgs) != len(tt.want) {
				t.Fatalf("published %d messages, want %d", len(msgs), len(tt.want))
			}
			for i, m := range msgs {
				if m.msgType != tt.wantType {
					t.Errorf("message %d type = %d, want %d", i, m.msgType, tt.wantType)
				}
				if got := string(m.payload); got != tt.want[i] {
					t.Errorf("message %d published JSON:\n%s\nwant:\n%s", i, got, tt.want[i])
				}
			}
		})
	}
}
