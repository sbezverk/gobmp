package message

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strconv"
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
	p.produceRouteMessage(bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: update}})
	return pub.msgs[n:]
}

func testCat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// fields merges field sets; later sets win.
func fields(sets ...map[string]any) map[string]any {
	m := map[string]any{}
	for _, s := range sets {
		for k, v := range s {
			m[k] = v
		}
	}
	return m
}

// checkJSONFields decodes payload as a JSON object and checks that each field
// in want is present with an equal value (compared after a JSON round trip,
// so member order and formatting do not matter), and that each field in
// optional that want does not list is absent.
func checkJSONFields(t *testing.T, payload []byte, want map[string]any, optional []string) {
	t.Helper()
	var got map[string]json.RawMessage
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("published payload is not a JSON object: %v\n%s", err, payload)
	}
	for k, v := range want {
		raw, ok := got[k]
		if !ok {
			t.Errorf("field %q absent, want %v", k, v)
			continue
		}
		wb, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal(%v): %v", v, err)
		}
		var g, w any
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatalf("field %q: %v", k, err)
		}
		if err := json.Unmarshal(wb, &w); err != nil {
			t.Fatalf("field %q: %v", k, err)
		}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("field %q = %s, want %s", k, raw, wb)
		}
	}
	for _, k := range optional {
		if _, listed := want[k]; listed {
			continue
		}
		if raw, ok := got[k]; ok {
			t.Errorf("field %q = %s, want absent", k, raw)
		}
	}
}

// TestPathIDDecodersPublishedJSON checks the JSON published for valid SAFI 1,
// plain NLRI field, multicast and L3VPN input, with and without ADD-PATH
// negotiated in both directions. Each case lists the fields it requires; any
// field in optionalFields that a case does not list must be absent.
func TestPathIDDecodersPublishedJSON(t *testing.T) {
	optionalFields := []string{
		"hash", "remote_bgp_id", "nexthop", "path_id",
		"labels", "vpn_rd", "vpn_rd_type", "afi", "safi",
	}
	v4NH := []byte{192, 0, 2, 1}
	v6NH := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	vpnNH := testCat(make([]byte, 8), v4NH) // RD 0 + 192.0.2.1 (RFC 4364 §4.3.2)
	pathID := []byte{0x00, 0x00, 0x00, 0x07}
	v4Prefix := []byte{0x18, 0x0a, 0x01, 0x02}                                      // 10.1.2.0/24
	v6Prefix := []byte{0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}        // 2001:db8:1::/64
	vpnV4 := []byte{0x70, 0x05, 0xdc, 0x31, 0, 0, 0, 0x64, 0, 0, 0, 0x01, 10, 1, 2} // label 24003, RD 100:1, 10.1.2.0/24
	vpnV4Withdraw := []byte{0x70, 0x80, 0x00, 0x00, 0, 0, 0, 0x64, 0, 0, 0, 0x01, 10, 1, 2}

	common := map[string]any{"router_ip": "10.1.1.1", "peer_ip": "10.0.0.1", "peer_asn": 65000, "origin_as": 65000}
	add := map[string]any{"action": "add"}
	del := map[string]any{"action": "del"}
	v4 := map[string]any{"prefix": "10.1.2.0", "prefix_len": 24, "is_ipv4": true}
	v6 := map[string]any{"prefix": "2001:db8:1::", "prefix_len": 64, "is_ipv4": false}
	nh4 := map[string]any{"nexthop": "192.0.2.1"}
	nh6 := map[string]any{"nexthop": "2001:db8::1"}
	pid := map[string]any{"path_id": 7}
	bgpID := map[string]any{"remote_bgp_id": "10.0.0.1"}
	unicast4 := map[string]any{"afi": 1, "safi": 1}
	unicast6 := map[string]any{"afi": 2, "safi": 1}
	vpn := map[string]any{"vpn_rd": "100:1", "vpn_rd_type": 0, "afi": 1, "safi": 128}
	// Route hashes are pinned: a path is identified by prefix and Path
	// Identifier (RFC 7911 §3), so the hash is chosen to differ from the same
	// prefix without one, and a withdrawal hashes like its announcement.
	hash := func(h string) map[string]any { return map[string]any{"hash": h} }
	const (
		v4Hash        = "bb239fe17b30ba78ab7d6ac4eec7f5e1"
		v4PathHash    = "5ff42bcb7b8d20b1384921ad9a9ae305"
		v6Hash        = "ba1c3c731087ea4b4a5461ed2eed9c19"
		v6PathHash    = "dd15844d205beab74bb17569effa7b9f"
		vpnV4PathHash = "08e8c17a52a7ce1618f2dbafe9cf6d8f"
	)

	tests := []struct {
		name     string
		addPath  [][2]byte // AFI/SAFI with ADD-PATH 3 in both OPENs; nil for no Peer Up
		update   func(t *testing.T) *bgp.Update
		wantType int
		want     map[string]any
	}{
		{
			name:     "SAFI 1 IPv4 announce",
			update:   func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0e, 1, 1, v4NH, v4Prefix)) },
			wantType: bmp.UnicastPrefixMsg,
			want:     fields(add, v4, hash(v4Hash), bgpID, nh4, unicast4),
		},
		{
			name:    "SAFI 1 IPv4 announce, ADD-PATH",
			addPath: [][2]byte{{1, 1}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 1, 1, v4NH, testCat(pathID, v4Prefix)))
			},
			wantType: bmp.UnicastPrefixMsg,
			want:     fields(add, v4, hash(v4PathHash), bgpID, nh4, pid, unicast4),
		},
		{
			name:    "SAFI 1 IPv4 withdraw, ADD-PATH",
			addPath: [][2]byte{{1, 1}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0f, 1, 1, nil, testCat(pathID, v4Prefix)))
			},
			wantType: bmp.UnicastPrefixMsg,
			want:     fields(del, v4, hash(v4PathHash), bgpID, pid, unicast4),
		},
		{
			name:     "SAFI 1 IPv6 announce",
			update:   func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0e, 2, 1, v6NH, v6Prefix)) },
			wantType: bmp.UnicastPrefixMsg,
			want:     fields(add, v6, hash(v6Hash), bgpID, nh6, unicast6),
		},
		{
			name:    "SAFI 1 IPv6 announce, ADD-PATH",
			addPath: [][2]byte{{2, 1}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 2, 1, v6NH, testCat(pathID, v6Prefix)))
			},
			wantType: bmp.UnicastPrefixMsg,
			want:     fields(add, v6, hash(v6PathHash), bgpID, nh6, pid, unicast6),
		},
		{
			name:     "SAFI 1 IPv6 withdraw",
			update:   func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0f, 2, 1, nil, v6Prefix)) },
			wantType: bmp.UnicastPrefixMsg,
			want:     fields(del, v6, hash(v6Hash), bgpID, unicast6),
		},
		{
			name:     "NLRI field announce",
			update:   func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, v4Prefix) },
			wantType: bmp.UnicastPrefixMsg,
			want:     fields(add, v4, hash(v4Hash), bgpID, nh4, unicast4),
		},
		{
			name:     "NLRI field announce, ADD-PATH",
			addPath:  [][2]byte{{1, 1}},
			update:   func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, testCat(pathID, v4Prefix)) },
			wantType: bmp.UnicastPrefixMsg,
			want:     fields(add, v4, hash(v4PathHash), bgpID, nh4, pid, unicast4),
		},
		{
			// With a withdrawal it is not an End-of-RIB (RFC 4724 §2).
			name:     "Withdrawn Routes field, ADD-PATH",
			addPath:  [][2]byte{{1, 1}},
			update:   func(t *testing.T) *bgp.Update { return plainTestUpdate(t, testCat(pathID, v4Prefix), nil) },
			wantType: bmp.UnicastPrefixMsg,
			want:     fields(del, v4, hash(v4PathHash), bgpID, pid, unicast4),
		},
		{
			name:     "multicast IPv4 announce",
			update:   func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0e, 1, 2, v4NH, v4Prefix)) },
			wantType: bmp.MulticastV4Msg,
			want:     fields(add, v4, nh4),
		},
		{
			name:    "multicast IPv6 announce, ADD-PATH",
			addPath: [][2]byte{{2, 2}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 2, 2, v6NH, testCat(pathID, v6Prefix)))
			},
			wantType: bmp.MulticastV6Msg,
			want:     fields(add, v6, nh6, pid),
		},
		{
			name:    "VPNv4 announce, ADD-PATH",
			addPath: [][2]byte{{1, 128}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 1, 128, vpnNH, testCat(pathID, vpnV4)), testRT)
			},
			wantType: bmp.L3VPNMsg,
			want:     fields(add, v4, hash(vpnV4PathHash), bgpID, nh4, pid, vpn, map[string]any{"labels": []int{24003}}),
		},
		{
			name:    "VPNv4 withdraw, ADD-PATH",
			addPath: [][2]byte{{1, 128}},
			update: func(t *testing.T) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0f, 1, 128, nil, testCat(pathID, vpnV4Withdraw)))
			},
			wantType: bmp.L3VPNMsg,
			want:     fields(del, v4, hash(vpnV4PathHash), bgpID, pid, vpn),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := publishWithPeerUp(t, minimalPeerHeader(), tt.addPath, tt.update(t))
			if len(msgs) != 1 {
				t.Fatalf("published %d messages, want 1", len(msgs))
			}
			if msgs[0].msgType != tt.wantType {
				t.Errorf("message type = %d, want %d", msgs[0].msgType, tt.wantType)
			}
			checkJSONFields(t, msgs[0].payload, fields(common, tt.want), optionalFields)
		})
	}
}

// TestPathIDFullRangePublishedJSON checks that a Path Identifier, a 4-octet
// field (RFC 7911 §3), is published unchanged for values that do not fit an
// int32, that paths differing only in the high bit hash apart, and that a
// withdrawal hashes like its announcement.
func TestPathIDFullRangePublishedJSON(t *testing.T) {
	v4NH := []byte{192, 0, 2, 1}
	v6NH := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	vpnNH := testCat(make([]byte, 8), v4NH)
	v4Prefix := []byte{0x18, 0x0a, 0x01, 0x02}
	v6Prefix := []byte{0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}
	luV4 := []byte{0x30, 0x05, 0xdc, 0x31, 10, 1, 2}                                // label 24003, 10.1.2.0/24
	luV4Withdraw := []byte{0x30, 0x80, 0x00, 0x00, 10, 1, 2}                        // RFC 8277 §2.4 withdrawal label
	vpnV4 := []byte{0x70, 0x05, 0xdc, 0x31, 0, 0, 0, 0x64, 0, 0, 0, 0x01, 10, 1, 2} // label 24003, RD 100:1, 10.1.2.0/24
	vpnV4Withdraw := []byte{0x70, 0x80, 0x00, 0x00, 0, 0, 0, 0x64, 0, 0, 0, 0x01, 10, 1, 2}

	type builder func(t *testing.T, pathID []byte) *bgp.Update
	families := []struct {
		name     string
		addPath  [2]byte
		announce builder
		withdraw builder // nil when the message carries no hash
	}{
		{"unicast IPv4 MP_REACH", [2]byte{1, 1},
			func(t *testing.T, id []byte) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 1, 1, v4NH, testCat(id, v4Prefix)))
			},
			func(t *testing.T, id []byte) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0f, 1, 1, nil, testCat(id, v4Prefix)))
			}},
		{"unicast IPv4 NLRI field", [2]byte{1, 1},
			func(t *testing.T, id []byte) *bgp.Update { return plainTestUpdate(t, nil, testCat(id, v4Prefix)) },
			func(t *testing.T, id []byte) *bgp.Update { return plainTestUpdate(t, testCat(id, v4Prefix), nil) }},
		{"labeled unicast IPv4", [2]byte{1, 4},
			func(t *testing.T, id []byte) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 1, 4, v4NH, testCat(id, luV4)))
			},
			func(t *testing.T, id []byte) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0f, 1, 4, nil, testCat(id, luV4Withdraw)))
			}},
		{"multicast IPv6", [2]byte{2, 2},
			func(t *testing.T, id []byte) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 2, 2, v6NH, testCat(id, v6Prefix)))
			}, nil},
		{"VPNv4", [2]byte{1, 128},
			func(t *testing.T, id []byte) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0e, 1, 128, vpnNH, testCat(id, vpnV4)), testRT)
			},
			func(t *testing.T, id []byte) *bgp.Update {
				return testUpdate(t, mpTestAttr(0x0f, 1, 128, nil, testCat(id, vpnV4Withdraw)))
			}},
	}
	type published struct {
		PathID json.RawMessage `json:"path_id"`
		Hash   string          `json:"hash"`
	}
	publish := func(t *testing.T, addPath [2]byte, update *bgp.Update) published {
		t.Helper()
		msgs := publishWithPeerUp(t, minimalPeerHeader(), [][2]byte{addPath}, update)
		if len(msgs) != 1 {
			t.Fatalf("published %d messages, want 1", len(msgs))
		}
		var got published
		if err := json.Unmarshal(msgs[0].payload, &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, f := range families {
		t.Run(f.name, func(t *testing.T) {
			hashes := map[string]uint32{}
			for _, id := range []uint32{1<<31 - 1, 1 << 31, ^uint32(0)} {
				wire := binary.BigEndian.AppendUint32(nil, id)
				want := strconv.FormatUint(uint64(id), 10)
				add := publish(t, f.addPath, f.announce(t, wire))
				if string(add.PathID) != want {
					t.Errorf("path_id = %s, want %s", add.PathID, want)
				}
				if f.withdraw == nil {
					continue
				}
				if prev, dup := hashes[add.Hash]; dup {
					t.Errorf("paths %d and %d share hash %s", prev, id, add.Hash)
				}
				hashes[add.Hash] = id
				del := publish(t, f.addPath, f.withdraw(t, wire))
				if string(del.PathID) != want || del.Hash != add.Hash {
					t.Errorf("withdrawal path_id/hash = %s %s, want %s %s", del.PathID, del.Hash, want, add.Hash)
				}
			}
		})
	}
}

// TestAddPathIDsIndependentWithinUpdate sends one UPDATE carrying three
// ADD-PATH NLRIs (two paths for the same prefix and one for another prefix)
// and checks that each route keeps its own path ID and hash, then withdraws
// one of the two same-prefix paths and checks that only that path is removed.
func TestAddPathIDsIndependentWithinUpdate(t *testing.T) {
	v4NH := []byte{192, 0, 2, 1}
	id := func(n byte) []byte { return []byte{0, 0, 0, n} }
	p1 := []byte{0x18, 10, 1, 2} // 10.1.2.0/24
	p2 := []byte{0x18, 10, 1, 3} // 10.1.3.0/24
	announce := testCat(id(7), p1, id(8), p1, id(9), p2)
	withdraw := testCat(id(8), p1)
	wantPrefix := map[uint32]string{7: "10.1.2.0", 8: "10.1.2.0", 9: "10.1.3.0"}

	type route struct {
		Action string  `json:"action"`
		Hash   string  `json:"hash"`
		Prefix string  `json:"prefix"`
		PathID *uint32 `json:"path_id"`
	}
	decode := func(t *testing.T, msgs []recordedMsg) []route {
		t.Helper()
		routes := make([]route, len(msgs))
		for i, m := range msgs {
			if m.msgType != bmp.UnicastPrefixMsg {
				t.Errorf("message %d type = %d, want %d", i, m.msgType, bmp.UnicastPrefixMsg)
			}
			if err := json.Unmarshal(m.payload, &routes[i]); err != nil {
				t.Fatalf("message %d: %v", i, err)
			}
			if routes[i].PathID == nil {
				t.Fatalf("message %d has no path_id: %s", i, m.payload)
			}
		}
		return routes
	}

	tests := []struct {
		name     string
		announce func(t *testing.T) *bgp.Update
		withdraw func(t *testing.T) *bgp.Update
	}{
		{
			name:     "MP_REACH_NLRI and MP_UNREACH_NLRI",
			announce: func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0e, 1, 1, v4NH, announce)) },
			withdraw: func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0f, 1, 1, nil, withdraw)) },
		},
		{
			name:     "NLRI and Withdrawn Routes fields",
			announce: func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, announce) },
			withdraw: func(t *testing.T) *bgp.Update { return plainTestUpdate(t, withdraw, nil) },
		},
	}
	addPath := [][2]byte{{1, 1}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added := decode(t, publishWithPeerUp(t, minimalPeerHeader(), addPath, tt.announce(t)))
			if len(added) != len(wantPrefix) {
				t.Fatalf("announce published %d messages, want %d", len(added), len(wantPrefix))
			}
			hashByID := map[uint32]string{}
			seenHash := map[string]uint32{}
			for _, r := range added {
				pid := *r.PathID
				if r.Action != "add" {
					t.Errorf("path %d action = %q, want add", pid, r.Action)
				}
				if want, ok := wantPrefix[pid]; !ok || r.Prefix != want {
					t.Errorf("path %d prefix = %q, want %q", pid, r.Prefix, want)
				}
				if _, dup := hashByID[pid]; dup {
					t.Errorf("path ID %d published twice", pid)
				}
				if other, dup := seenHash[r.Hash]; dup {
					t.Errorf("paths %d and %d share hash %s", other, pid, r.Hash)
				}
				hashByID[pid] = r.Hash
				seenHash[r.Hash] = pid
			}

			removed := decode(t, publishWithPeerUp(t, minimalPeerHeader(), addPath, tt.withdraw(t)))
			if len(removed) != 1 {
				t.Fatalf("withdraw published %d messages, want 1", len(removed))
			}
			r := removed[0]
			if r.Action != "del" || *r.PathID != 8 || r.Prefix != "10.1.2.0" {
				t.Errorf("withdraw = %+v path_id %d, want del 10.1.2.0 path_id 8", r, *r.PathID)
			}
			if r.Hash != hashByID[8] {
				t.Errorf("withdraw hash = %s, want path 8 announce hash %s", r.Hash, hashByID[8])
			}
		})
	}
}
