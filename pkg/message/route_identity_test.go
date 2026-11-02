package message

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

type routeHashFamily struct {
	name      string
	afi       uint16
	safi      uint8
	prefix    []byte
	prefixLen uint8
}

var routeHashFamilies = []routeHashFamily{
	{"LUv4", 1, 4, []byte{198, 51, 100}, 24},
	{"LUv6", 2, 4, []byte{0x20, 1, 0x0d, 0xb8, 1, 0}, 48},
	{"VPNv4", 1, 128, []byte{198, 51, 100}, 24},
	{"VPNv6", 2, 128, []byte{0x20, 1, 0x0d, 0xb8, 1, 0}, 48},
}

// routeHashFrame builds an ordinary BGP frame (RFC 4271 Section 4.1).
func routeHashFrame(kind byte, body []byte) []byte {
	wire := bytes.Repeat([]byte{0xff}, 19)
	binary.BigEndian.PutUint16(wire[16:18], uint16(19+len(body)))
	wire[18] = kind
	return append(wire, body...)
}

func routeHashPeerUp(t *testing.T, family routeHashFamily, addPath bool) *bmp.PeerUpMessage {
	t.Helper()
	families := []uint8{family.safi}
	if family.safi == 4 {
		families = append(families, 1)
	}
	caps := []byte{65, 4, 0, 0, 0xfd, 0xe8}
	var paths []byte
	for _, safi := range families {
		caps = append(caps, 1, 4, byte(family.afi>>8), byte(family.afi), 0, safi)
		paths = append(paths, byte(family.afi>>8), byte(family.afi), safi, 3)
	}
	if addPath {
		// Both OPENs negotiate send/receive for each family (RFC 7911 Section 5).
		caps = append(caps, 69, byte(len(paths)))
		caps = append(caps, paths...)
	}
	open := func(id byte) []byte {
		body := []byte{4, 0xfd, 0xe8, 0, 90, 192, 0, 2, id, byte(2 + len(caps)), 2, byte(len(caps))}
		return routeHashFrame(1, append(body, caps...))
	}
	wire := make([]byte, 20)
	copy(wire[12:16], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(wire[16:18], 179)
	binary.BigEndian.PutUint16(wire[18:20], 179)
	wire = append(wire, open(1)...)
	wire = append(wire, open(2)...)
	up, err := bmp.UnmarshalPeerUpMessage(wire, false)
	if err != nil {
		t.Fatal(err)
	}
	return up
}

func routeHashUpdate(t *testing.T, attrs, withdrawn, nlri []byte) *bmp.RouteMonitor {
	t.Helper()
	body := []byte{byte(len(withdrawn) >> 8), byte(len(withdrawn))}
	body = append(body, withdrawn...)
	body = append(body, byte(len(attrs)>>8), byte(len(attrs)))
	body = append(body, attrs...)
	body = append(body, nlri...)
	update, err := bmp.UnmarshalBMPRouteMonitorMessageWithAS4Hint(routeHashFrame(2, body), true)
	if err != nil {
		t.Fatal(err)
	}
	return update
}

func routeHashMPUpdate(t *testing.T, family routeHashFamily, labels []uint32, pathID *uint32, withdraw bool) *bmp.RouteMonitor {
	t.Helper()
	var nlri []byte
	if pathID != nil {
		nlri = binary.BigEndian.AppendUint32(nlri, *pathID)
	}
	length := family.prefixLen
	if family.safi != 1 {
		length += 24
	}
	if family.safi == 128 {
		length += 64
	}
	nlri = append(nlri, length)
	if family.safi != 1 {
		if withdraw {
			// RFC 8277 Section 2.4: the compatibility field carries no old label.
			nlri = append(nlri, 0x80, 0, 0)
		} else {
			if len(labels) != 1 {
				t.Fatal("wire fixture requires one label")
			}
			label := labels[0]<<4 | 1
			nlri = append(nlri, byte(label>>16), byte(label>>8), byte(label))
		}
	}
	if family.safi == 128 {
		nlri = append(nlri, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1)
	}
	nlri = append(nlri, family.prefix...)
	mp := []byte{byte(family.afi >> 8), byte(family.afi), family.safi}
	if withdraw {
		mp = append(mp, nlri...)
		return routeHashUpdate(t, append([]byte{0x80, bgp.MP_UNREACH_NLRI, byte(len(mp))}, mp...), nil, nil)
	}
	// Valid iBGP attributes, with the 4-byte AS_PATH format from the BMP A bit.
	attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe8, 0x40, 5, 4, 0, 0, 0, 100}
	nextHop := []byte{192, 0, 2, 1}
	if family.afi == 2 {
		nextHop = []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	}
	if family.safi == 128 {
		nextHop = append(make([]byte, 8), nextHop...)
		attrs = append(attrs, 0xc0, 16, 8, 0, 2, 0xfd, 0xe8, 0, 0, 0, 1)
	}
	mp = append(mp, byte(len(nextHop)))
	mp = append(mp, nextHop...)
	mp = append(mp, 0)
	mp = append(mp, nlri...)
	attrs = append(attrs, 0x80, bgp.MP_REACH_NLRI, byte(len(mp)))
	attrs = append(attrs, mp...)
	return routeHashUpdate(t, attrs, nil, nil)
}

func routeHashPublish(t *testing.T, family routeHashFamily, addPath, splitAF bool, updates []*bmp.RouteMonitor) []recordedMsg {
	t.Helper()
	ph := makePeerHeader(t, bmp.PeerType0, 0)
	copy(ph.PeerAddress[12:], []byte{192, 0, 2, 2})
	copy(ph.PeerBGPID, []byte{192, 0, 2, 2})
	rec := &recordingPublisher{}
	p := NewProducer(rec, splitAF)
	queue := make(chan bmp.Message, 1+len(updates))
	queue <- bmp.Message{PeerHeader: ph, Payload: routeHashPeerUp(t, family, addPath), SpeakerIP: "198.51.100.1"}
	for _, update := range updates {
		queue <- bmp.Message{PeerHeader: ph, Payload: update, SpeakerIP: "198.51.100.1"}
	}
	close(queue)
	p.Producer(queue, make(chan struct{}))
	return rec.msgs[1:]
}

func routeHashRoundTrip(t *testing.T, msg recordedMsg, vpn bool) {
	t.Helper()
	var value any = &UnicastPrefix{}
	if vpn {
		value = &L3VPNPrefix{}
	}
	if err := json.Unmarshal(msg.payload, value); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var original, recovered any
	if err := json.Unmarshal(msg.payload, &original); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wire, &recovered); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, recovered) {
		t.Errorf("public route JSON did not round-trip: %s -> %s", msg.payload, wire)
	}
}

// TestRouteHashWireLabelLifecycle verifies RFC 8277 Sections 2.4 and 2.5 at
// the public Producer boundary, including replacement in a store keyed by hash.
func TestRouteHashWireLabelLifecycle(t *testing.T) {
	for _, family := range routeHashFamilies {
		for _, addPath := range []bool{false, true} {
			for _, splitAF := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/addpath=%t/split=%t", family.name, addPath, splitAF), func(t *testing.T) {
					type event struct {
						name     string
						family   routeHashFamily
						labels   []uint32
						path     *uint32
						withdraw bool
						active   int
					}
					var mainPath, otherPath *uint32
					if addPath {
						mainID, otherID := uint32(256), uint32(257)
						mainPath, otherPath = &mainID, &otherID
					}
					var events []event
					count := 0
					if family.safi == 4 {
						plain := family
						plain.safi = 1
						count++
						events = append(events, event{"plain", plain, nil, mainPath, false, count})
					}
					count++
					events = append(events, event{"announce", family, []uint32{24001}, mainPath, false, count})
					if addPath {
						count++
						events = append(events, event{"other-path", family, []uint32{24010}, otherPath, false, count})
					}
					events = append(events, event{"replacement", family, []uint32{24002}, mainPath, false, count})
					events = append(events, event{"withdrawal", family, nil, mainPath, true, count - 1})
					var updates []*bmp.RouteMonitor
					for _, e := range events {
						updates = append(updates, routeHashMPUpdate(t, e.family, e.labels, e.path, e.withdraw))
					}
					msgs := routeHashPublish(t, family, addPath, splitAF, updates)
					if len(msgs) != len(events) {
						t.Fatalf("published %d route records, want %d", len(msgs), len(events))
					}
					type route struct {
						Action string   `json:"action"`
						Hash   string   `json:"hash"`
						AFI    uint16   `json:"afi"`
						SAFI   uint8    `json:"safi"`
						PathID int32    `json:"path_id"`
						Labels []uint32 `json:"labels"`
					}
					active := make(map[string]route)
					var identity, plainIdentity, otherIdentity string
					for i, msg := range msgs {
						e := events[i]
						var got route
						if err := json.Unmarshal(msg.payload, &got); err != nil {
							t.Fatal(err)
						}
						wantTopic := bmp.UnicastPrefixMsg
						if family.safi == 128 {
							wantTopic = bmp.L3VPNMsg
						}
						if splitAF {
							if family.safi == 128 {
								wantTopic = bmp.L3VPNV4Msg
								if family.afi == 2 {
									wantTopic = bmp.L3VPNV6Msg
								}
							} else {
								wantTopic = bmp.UnicastPrefixV4Msg
								if family.afi == 2 {
									wantTopic = bmp.UnicastPrefixV6Msg
								}
							}
						}
						if msg.msgType != wantTopic || got.AFI != e.family.afi || got.SAFI != e.family.safi {
							t.Errorf("%s: topic/family = %d %d/%d, want %d %d/%d", e.name, msg.msgType, got.AFI, got.SAFI, wantTopic, e.family.afi, e.family.safi)
						}
						var wantPath int32
						if e.path != nil {
							wantPath = int32(*e.path)
						}
						if got.Hash == "" || got.PathID != wantPath || !reflect.DeepEqual(got.Labels, e.labels) {
							t.Errorf("%s: hash/path/labels = %q %d %v, want nonempty %d %v", e.name, got.Hash, got.PathID, got.Labels, wantPath, e.labels)
						}
						switch e.name {
						case "plain":
							plainIdentity = got.Hash
						case "announce":
							identity = got.Hash
						case "other-path":
							otherIdentity = got.Hash
							if got.Hash == identity {
								t.Error("different PathIDs shared one route hash")
							}
						case "replacement", "withdrawal":
							if got.Hash != identity {
								t.Errorf("%s changed route hash: got %s, want %s", e.name, got.Hash, identity)
							}
						}
						if e.withdraw {
							if got.Action != "del" {
								t.Errorf("withdrawal action = %q, want del", got.Action)
							}
							delete(active, got.Hash)
						} else {
							if got.Action != "add" {
								t.Errorf("%s action = %q, want add", e.name, got.Action)
							}
							active[got.Hash] = got
						}
						if len(active) != e.active {
							t.Errorf("%s left %d active routes, want %d", e.name, len(active), e.active)
						}
						routeHashRoundTrip(t, msg, family.safi == 128)
					}
					if plainIdentity != "" {
						if plainIdentity == identity {
							t.Error("plain and labeled unicast shared one route hash")
						}
						if _, ok := active[plainIdentity]; !ok {
							t.Error("labeled withdrawal removed the plain route")
						}
					}
					if addPath {
						if _, ok := active[otherIdentity]; !ok {
							t.Error("withdrawal removed the other PathID")
						}
					}
				})
			}
		}
	}
}

func TestRouteHashWireEOR(t *testing.T) {
	families := append([]routeHashFamily{{"legacy", 1, 1, nil, 0}, {"MPv6", 2, 1, nil, 0}}, routeHashFamilies...)
	for _, family := range families {
		t.Run(family.name, func(t *testing.T) {
			var attrs []byte
			if family.name != "legacy" {
				attrs = []byte{0x80, bgp.MP_UNREACH_NLRI, 3, byte(family.afi >> 8), byte(family.afi), family.safi}
			}
			msgs := routeHashPublish(t, family, false, false, []*bmp.RouteMonitor{routeHashUpdate(t, attrs, nil, nil)})
			if len(msgs) != 2 || msgs[1].msgType != bmp.EndOfRIBMsg {
				t.Fatalf("EOR published %v, want compatibility marker and EndOfRIB", msgs)
			}
			var marker struct {
				Hash  string `json:"hash"`
				IsEOR bool   `json:"is_eor"`
				AFI   uint16 `json:"afi"`
				SAFI  uint8  `json:"safi"`
			}
			if err := json.Unmarshal(msgs[0].payload, &marker); err != nil {
				t.Fatal(err)
			}
			if !marker.IsEOR || marker.Hash != "" || marker.AFI != family.afi || marker.SAFI != family.safi {
				t.Errorf("compatibility EOR changed: %+v", marker)
			}
		})
	}
}

func TestRouteHashLegacyGolden(t *testing.T) {
	// These vectors pin the existing MD5 of NUL-delimited components,
	// including the trailing empty component. AFI/SAFI metadata must not
	// rekey ordinary unicast or previously empty-label VPN records.
	for _, family := range []struct {
		name string
		afi  uint16
		safi uint8
	}{
		{"legacy-fields-absent", 0, 0},
		{"explicit-unicast", 1, 1},
	} {
		t.Run(family.name, func(t *testing.T) {
			m := &UnicastPrefix{RouterHash: "router", PeerHash: "peer", Prefix: "198.51.100.0", PrefixLen: 24, IsIPv4: true, AFI: family.afi, SAFI: family.safi}
			setUnicastPrefixHash(m)
			if m.Hash != "98039f9ef8121ebee4e26613c55d4e08" {
				t.Errorf("ordinary IPv4 hash changed: %s", m.Hash)
			}
		})
	}
	v6 := &UnicastPrefix{RouterHash: "router", PeerHash: "peer", Prefix: "2001:db8::", PrefixLen: 32, IsIPv4: false, PathID: 17, AFI: 2, SAFI: 1}
	setUnicastPrefixHash(v6)
	if v6.Hash != "647454672d066faa750dd7177eaa74ef" {
		t.Errorf("ordinary IPv6 hash changed: %s", v6.Hash)
	}
	vpn := &L3VPNPrefix{RouterHash: "router", PeerHash: "peer", VPNRD: "65000:1", Prefix: "10.0.0.0", PrefixLen: 24, IsIPv4: true, AFI: 1, SAFI: 128}
	setL3VPNPrefixHash(vpn)
	if vpn.Hash != "1b7e0e401ee3a661bae00b62ef3e131e" {
		t.Errorf("empty-label VPN hash changed: %s", vpn.Hash)
	}
}

func TestRouteHashLegacyWireFamily(t *testing.T) {
	attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe8, 0x40, 3, 4, 192, 0, 2, 1, 0x40, 5, 4, 0, 0, 0, 100}
	nlri := []byte{24, 198, 51, 100}
	family := routeHashFamily{"legacy", 1, 1, nil, 0}
	msgs := routeHashPublish(t, family, false, false, []*bmp.RouteMonitor{
		routeHashUpdate(t, attrs, nil, nlri),
		routeHashUpdate(t, nil, nlri, nil),
	})
	if len(msgs) != 2 {
		t.Fatalf("published %d records, want add and del", len(msgs))
	}
	var identity string
	for i, msg := range msgs {
		var got UnicastPrefix
		if err := json.Unmarshal(msg.payload, &got); err != nil {
			t.Fatal(err)
		}
		if got.AFI != 1 || got.SAFI != 1 || got.Hash == "" || got.IsEOR {
			t.Errorf("legacy route has wrong family/hash: %+v", got)
		}
		if i == 0 {
			identity = got.Hash
		} else if got.Hash != identity {
			t.Errorf("legacy withdrawal hash = %s, want %s", got.Hash, identity)
		}
		routeHashRoundTrip(t, msg, false)
	}
}

func TestRouteHashIdentityFields(t *testing.T) {
	original := UnicastPrefix{RouterHash: "router", PeerHash: "peer", Prefix: "198.51.100.0", PrefixLen: 24, IsIPv4: true, AFI: 1, SAFI: 4}
	identity := original
	setUnicastPrefixHash(&identity)
	for _, tc := range []struct {
		name   string
		change func(*UnicastPrefix)
	}{
		{"router", func(m *UnicastPrefix) { m.RouterHash = "other" }},
		{"peer", func(m *UnicastPrefix) { m.PeerHash = "other" }},
		{"prefix", func(m *UnicastPrefix) { m.Prefix = "198.51.101.0" }},
		{"prefix-length", func(m *UnicastPrefix) { m.PrefixLen = 32 }},
		{"AFI", func(m *UnicastPrefix) { m.AFI, m.IsIPv4 = 2, false }},
		{"SAFI", func(m *UnicastPrefix) { m.SAFI = 1 }},
		{"PathID", func(m *UnicastPrefix) { m.PathID = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := original
			tc.change(&m)
			setUnicastPrefixHash(&m)
			if m.Hash == identity.Hash {
				t.Errorf("%s did not distinguish route identity", tc.name)
			}
		})
	}
	for _, labels := range [][]uint32{nil, {0}, {24001}, {24001, 24002}, {24002, 24001}} {
		m := original
		m.Labels, m.Action, m.Timestamp = labels, "del", "2026-10-31T00:00:00Z"
		setUnicastPrefixHash(&m)
		if m.Hash != identity.Hash {
			t.Errorf("forwarding attributes changed route identity: labels=%v", labels)
		}
	}
	provided := original
	provided.Hash = "caller-provided"
	setUnicastPrefixHash(&provided)
	if provided.Hash != "caller-provided" {
		t.Error("explicit hash was overwritten")
	}
}

func TestVPNRouteHashIdentityFields(t *testing.T) {
	original := L3VPNPrefix{RouterHash: "router", PeerHash: "peer", VPNRD: "65000:1", Prefix: "198.51.100.0", PrefixLen: 24, IsIPv4: true, AFI: 1, SAFI: 128}
	identity := original
	setL3VPNPrefixHash(&identity)
	for _, tc := range []struct {
		name   string
		change func(*L3VPNPrefix)
	}{
		{"peer", func(m *L3VPNPrefix) { m.PeerHash = "other" }},
		{"RD", func(m *L3VPNPrefix) { m.VPNRD = "65000:2" }},
		{"RD-type", func(m *L3VPNPrefix) { m.VPNRDType = 2 }},
		{"AFI", func(m *L3VPNPrefix) { m.AFI, m.IsIPv4 = 2, false }},
		{"PathID", func(m *L3VPNPrefix) { m.PathID = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := original
			tc.change(&m)
			setL3VPNPrefixHash(&m)
			if m.Hash == identity.Hash {
				t.Errorf("%s did not distinguish VPN route identity", tc.name)
			}
		})
	}
	for _, labels := range [][]uint32{nil, {0}, {24001}, {24001, 24002}, {0x004200}} {
		m := original
		m.Labels, m.Action = labels, "del"
		setL3VPNPrefixHash(&m)
		if m.Hash != identity.Hash {
			t.Errorf("labels/transposition changed VPN route identity: %v", labels)
		}
	}
	provided := original
	provided.Hash = "caller-provided"
	setL3VPNPrefixHash(&provided)
	if provided.Hash != "caller-provided" {
		t.Error("explicit VPN hash was overwritten")
	}
}
