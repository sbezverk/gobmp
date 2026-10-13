package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

func mupProducer() *producer {
	return &producer{
		publisher: &mockPublisher{},
	}
}

func mupReachNLRI(nlri []byte, ipv6 bool) *bgp.MPReachNLRI {
	afi := uint16(1)
	if ipv6 {
		afi = 2
	}
	return &bgp.MPReachNLRI{
		AddressFamilyID:      afi,
		SubAddressFamilyID:   85,
		NextHopAddressLength: 4,
		NextHopAddress:       []byte{10, 0, 0, 1},
		NLRI:                 nlri,
	}
}

func mupPrefixSIDAttribute() []byte {
	return []byte{
		0x05, 0x00, 0x22, // SRv6 L3 Service TLV
		0x00,                   // reserved
		0x01, 0x00, 0x1e, 0x00, // SRv6 SID Information Sub-TLV
		0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SID 2001:0:5:3::
		0x00, 0x00, 0x11, 0x00, // flags, endpoint behavior 17, reserved
		0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40, // SID Structure Sub-Sub-TLV
	}
}

func mupUpdateWithPrefixSID() *bgp.Update {
	update := minimalUpdate()
	update.PathAttributes = []bgp.PathAttribute{{
		AttributeType: 40,
		Attribute:     mupPrefixSIDAttribute(),
	}}
	return update
}

func TestProducerMUPInterworkSegmentDiscovery(t *testing.T) {
	nlri := mupReachNLRI([]byte{
		0x01, 0x00, 0x01, 0x0c,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
		0x18, 0x0a, 0x0a, 0x0a,
	}, false)

	msgs, err := mupProducer().mup(nlri, 0, minimalPeerHeader(), mupUpdateWithPrefixSID())
	if err != nil {
		t.Fatalf("mup() unexpected error: %+v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("mup() returned %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.Action != "add" {
		t.Errorf("Action = %s, want add", m.Action)
	}
	if m.RouteType != 1 {
		t.Errorf("RouteType = %d, want 1", m.RouteType)
	}
	if m.VPNRD != "100:100" {
		t.Errorf("VPNRD = %s, want 100:100", m.VPNRD)
	}
	if m.Prefix != "10.10.10.0" || m.PrefixLen != 24 {
		t.Errorf("Prefix = %s/%d, want 10.10.10.0/24", m.Prefix, m.PrefixLen)
	}
	if !m.IsIPv4 {
		t.Error("IsIPv4 = false, want true")
	}
	if m.TEID != nil || m.QFI != nil {
		t.Errorf("TEID = %v, QFI = %v, want both nil for an ISD route", m.TEID, m.QFI)
	}
	if m.OriginAS != 65000 {
		t.Errorf("OriginAS = %d, want 65000", m.OriginAS)
	}
	if m.Nexthop != "10.0.0.1" {
		t.Errorf("Nexthop = %s, want 10.0.0.1", m.Nexthop)
	}
}

func TestProducerMUPType1SessionTransformed(t *testing.T) {
	nlri := mupReachNLRI([]byte{
		0x01, 0x00, 0x03, 0x1b,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
		0x18, 0xc0, 0x64, 0x00,
		0x00, 0x00, 0x00, 0x64,
		0x09,
		0x20, 0x0a, 0x0a, 0x0a, 0x01,
		0x20, 0x0a, 0x0a, 0x0a, 0x02,
	}, false)

	msgs, err := mupProducer().mup(nlri, 0, minimalPeerHeader(), minimalUpdate())
	if err != nil {
		t.Fatalf("mup() unexpected error: %+v", err)
	}
	m := msgs[0]
	if m.RouteType != 3 {
		t.Errorf("RouteType = %d, want 3", m.RouteType)
	}
	if m.TEID == nil || *m.TEID != 100 {
		t.Errorf("TEID = %v, want 100", m.TEID)
	}
	if m.QFI == nil || *m.QFI != 9 {
		t.Errorf("QFI = %v, want 9", m.QFI)
	}
	if m.EndpointAddress != "10.10.10.1" || m.EndpointLen != 32 {
		t.Errorf("EndpointAddress = %s/%d, want 10.10.10.1/32", m.EndpointAddress, m.EndpointLen)
	}
	if m.SourceAddress != "10.10.10.2" {
		t.Errorf("SourceAddress = %s, want 10.10.10.2", m.SourceAddress)
	}
}

func TestProcessMPUpdateMUPType1TLV(t *testing.T) {
	// Type 1 ST route with an unknown TLV after the mandatory fields.
	nlri := mupReachNLRI([]byte{
		0x01, 0x00, 0x03, 0x1d,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
		0x18, 0xc0, 0x64, 0x00,
		0x00, 0x00, 0x00, 0x64,
		0x09,
		0x20, 0x0a, 0x0a, 0x0a, 0x01,
		0x00,
		0xc8, 0x04, 0xde, 0xad, 0xbe, 0xef,
	}, false)
	pub := &recordingPublisher{}
	p := &producer{publisher: pub}

	p.processMPUpdate(nlri, AddPrefix, minimalPeerHeader(), minimalUpdate())
	if len(pub.msgs) != 1 {
		t.Fatalf("processMPUpdate() published %d messages, want 1", len(pub.msgs))
	}

	var got map[string]any
	if err := json.Unmarshal(pub.msgs[0].payload, &got); err != nil {
		t.Fatalf("json.Unmarshal() unexpected error: %+v", err)
	}
	tlvs, ok := got["tlvs"].([]any)
	if !ok || len(tlvs) != 1 {
		t.Fatalf("published message TLVs = %v, want one TLV", got["tlvs"])
	}
	tlv, ok := tlvs[0].(map[string]any)
	if !ok {
		t.Fatalf("published TLV = %T, want an object", tlvs[0])
	}
	if tlv["type"] != float64(200) || tlv["value"] != "0xdeadbeef" {
		t.Fatalf("published TLV = %v, want type 200 and value 0xdeadbeef", tlv)
	}
}

func TestProcessMPUpdateMUPZeroPrefixLengthSerialization(t *testing.T) {
	tests := []struct {
		name   string
		nlri   *bgp.MPReachNLRI
		update *bgp.Update
	}{
		{
			name: "ISD",
			nlri: mupReachNLRI([]byte{
				0x01, 0x00, 0x01, 0x09,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x00, // /0; no prefix octets follow
			}, false),
			update: mupUpdateWithPrefixSID(),
		},
		{
			name: "ST1",
			nlri: mupReachNLRI([]byte{
				0x01, 0x00, 0x03, 0x14,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x00,                   // /0; no prefix octets follow
				0x00, 0x00, 0x00, 0x64, // TEID 100
				0x09,                         // QFI 9
				0x20, 0x0a, 0x0a, 0x0a, 0x01, // endpoint address
				0x00, // source address length 0
			}, false),
			update: minimalUpdate(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub := &recordingPublisher{}
			p := &producer{publisher: pub}
			p.processMPUpdate(tt.nlri, AddPrefix, minimalPeerHeader(), tt.update)
			if len(pub.msgs) != 1 {
				t.Fatalf("processMPUpdate() published %d messages, want 1", len(pub.msgs))
			}

			var got map[string]any
			if err := json.Unmarshal(pub.msgs[0].payload, &got); err != nil {
				t.Fatalf("json.Unmarshal() unexpected error: %+v", err)
			}
			prefixLen, ok := got["prefix_len"]
			if !ok {
				t.Fatalf("published message is missing prefix_len: %s", pub.msgs[0].payload)
			}
			if prefixLen != float64(0) {
				t.Fatalf("published prefix_len = %v, want 0", prefixLen)
			}
		})
	}
}

// A Type 2 ST route reports the QFI only through the 3gpp-5g Session
// Parameters TLV.
func TestProducerMUPType2SessionTransformedTLV(t *testing.T) {
	nlri := mupReachNLRI([]byte{
		0x01, 0x00, 0x04, 0x18,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
		0x40, 0x0a, 0x0a, 0x0a, 0x01,
		0x00, 0x00, 0x00, 0x64,
		0x01, 0x05, 0x00, 0x00, 0x00, 0xc8, 0x00,
	}, false)

	msgs, err := mupProducer().mup(nlri, 0, minimalPeerHeader(), minimalUpdate())
	if err != nil {
		t.Fatalf("mup() unexpected error: %+v", err)
	}
	m := msgs[0]
	if m.RouteType != 4 {
		t.Errorf("RouteType = %d, want 4", m.RouteType)
	}
	if m.TEID == nil || *m.TEID != 100 {
		t.Errorf("TEID = %v, want 100", m.TEID)
	}
	if m.QFI == nil || *m.QFI != 0 {
		t.Errorf("QFI = %v, want 0 from the Session Parameters TLV", m.QFI)
	}
	if len(m.TLVs) != 1 {
		t.Fatalf("TLVs = %d, want 1", len(m.TLVs))
	}

	b, err := json.Marshal(&m)
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %+v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal() unexpected error: %+v", err)
	}
	for _, key := range []string{"route_type", "vpn_rd", "endpoint_address", "teid", "qfi", "tlvs"} {
		if _, ok := got[key]; !ok {
			t.Errorf("marshalled message is missing %q: %s", key, b)
		}
	}
	if _, ok := got["prefix"]; ok {
		t.Errorf("marshalled message carries a prefix for a Type 2 ST route: %s", b)
	}
}

// The Path Identifier reaches the published message when Add Path was
// negotiated for the BGP-MUP SAFI.
func TestProducerMUPAddPath(t *testing.T) {
	// AFI 1, SAFI 85, 4 octet next hop, reserved octet, then one NLRI
	// prefixed with Path Identifier 5.
	raw := append([]byte{0x00, 0x01, 85, 0x04, 10, 0, 0, 1, 0x00}, []byte{
		0x00, 0x00, 0x00, 0x05,
		0x01, 0x00, 0x01, 0x0c,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
		0x18, 0x0a, 0x0a, 0x0a,
	}...)
	nlri, err := bgp.UnmarshalMPReachNLRI(raw, false, map[int]bool{bgp.NLRIMessageType(1, 85): true})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI() unexpected error: %+v", err)
	}

	msgs, err := mupProducer().mup(nlri, AddPrefix, minimalPeerHeader(), mupUpdateWithPrefixSID())
	if err != nil {
		t.Fatalf("mup() unexpected error: %+v", err)
	}
	if msgs[0].PathID != 5 {
		t.Fatalf("PathID = %d, want 5", msgs[0].PathID)
	}

	b, err := json.Marshal(&msgs[0])
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %+v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal() unexpected error: %+v", err)
	}
	if got["path_id"] != float64(5) {
		t.Fatalf("marshalled path_id = %v, want 5: %s", got["path_id"], b)
	}
}

// An aggregate Type 2 ST route whose Endpoint Length stops at the endpoint
// address carries no TEID, so none is reported.
func TestProducerMUPType2SessionTransformedWithoutTEID(t *testing.T) {
	nlri := mupReachNLRI([]byte{
		0x01, 0x00, 0x04, 0x0d,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
		0x20, 0x0a, 0x0a, 0x0a, 0x01,
	}, false)

	msgs, err := mupProducer().mup(nlri, AddPrefix, minimalPeerHeader(), minimalUpdate())
	if err != nil {
		t.Fatalf("mup() unexpected error: %+v", err)
	}
	if msgs[0].TEID != nil {
		t.Fatalf("TEID = %d, want nil", *msgs[0].TEID)
	}
	b, err := json.Marshal(&msgs[0])
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %+v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal() unexpected error: %+v", err)
	}
	if _, ok := got["teid"]; ok {
		t.Fatalf("marshalled message carries a teid for a route without one: %s", b)
	}
}

// RFC 4724 §2: End-of-RIB is an empty MP_UNREACH_NLRI. An empty
// MP_REACH_NLRI is malformed and must not be published as one.
func TestProducerMUPEmptyReachIsNotEOR(t *testing.T) {
	nlri := &bgp.MPReachNLRI{
		AddressFamilyID:      1,
		SubAddressFamilyID:   85,
		NextHopAddressLength: 4,
		NextHopAddress:       []byte{10, 0, 0, 1},
	}
	if _, err := mupProducer().mup(nlri, AddPrefix, minimalPeerHeader(), minimalUpdate()); err == nil {
		t.Fatal("mup() expected an error for an empty MP_REACH_NLRI, got none")
	}
}

// The published hash covers the route key of each route type as defined by
// draft-ietf-bess-mup-safi-01, nothing more.
func TestProcessMPUpdateMUPHash(t *testing.T) {
	publish := func(nlri []byte) MUPPrefix {
		pub := &recordingPublisher{}
		p := &producer{publisher: pub}
		p.processMPUpdate(mupReachNLRI(nlri, false), AddPrefix, minimalPeerHeader(), minimalUpdate())
		if len(pub.msgs) != 1 {
			t.Fatalf("processMPUpdate() published %d messages, want 1", len(pub.msgs))
		}
		var got MUPPrefix
		if err := json.Unmarshal(pub.msgs[0].payload, &got); err != nil {
			t.Fatalf("json.Unmarshal() unexpected error: %+v", err)
		}
		return got
	}
	st2 := func(teid byte) []byte {
		return []byte{
			0x01, 0x00, 0x04, 0x11,
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
			0x40, 0x0a, 0x0a, 0x0a, 0x01,
			0x00, 0x00, 0x00, teid,
		}
	}
	st1 := func(prefix3, teid, qfi byte, ep []byte) []byte {
		b := []byte{
			0x01, 0x00, 0x03, 0x17,
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
			0x18, 0xc0, 0x64, prefix3,
			0x00, 0x00, 0x00, teid,
			qfi,
			0x20,
		}
		b = append(b, ep...)
		return append(b, 0x00)
	}

	first := publish(st2(100))
	if first.Hash == "" {
		t.Fatal("published MUP message has an empty hash")
	}
	if again := publish(st2(100)); again.Hash != first.Hash {
		t.Fatalf("hash is not stable: %s then %s for the same route", first.Hash, again.Hash)
	}
	// Section 3.1.4: the TEID is the Architecture specific Endpoint
	// Identifier and part of the ST2 route key.
	if other := publish(st2(101)); other.Hash == first.Hash {
		t.Fatalf("hash %s does not distinguish ST2 routes with different TEIDs", first.Hash)
	}

	// Section 3.1.3: the ST1 route key is RD, Prefix Length and Prefix alone.
	// TEID, QFI and endpoint are forwarding attributes, a withdraw carries
	// none of them and must hash the same as the announcement.
	a := publish(st1(0x00, 100, 9, []byte{10, 10, 10, 1}))
	b := publish(st1(0x00, 200, 3, []byte{10, 10, 10, 2}))
	if a.Hash == "" || a.Hash != b.Hash {
		t.Fatalf("ST1 routes with the same route key hash differently: %s vs %s", a.Hash, b.Hash)
	}
	if c := publish(st1(0x01, 100, 9, []byte{10, 10, 10, 1})); c.Hash == a.Hash {
		t.Fatalf("ST1 routes with different prefixes share hash %s", a.Hash)
	}
}

// MP_UNREACH_NLRI carries no next hop, so a withdrawal reports the next hop
// family of the NLRI rather than the MP_REACH_NLRI default.
func TestProducerMUPWithdrawIPv6NextHopFamily(t *testing.T) {
	nlri := &bgp.MPUnReachNLRI{
		AddressFamilyID:    2,
		SubAddressFamilyID: 85,
		WithdrawnRoutes: []byte{
			0x01, 0x00, 0x02, 0x18,
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
			0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}
	msgs, err := mupProducer().mup(nlri, DelPrefix, minimalPeerHeader(), minimalUpdate())
	if err != nil {
		t.Fatalf("mup() unexpected error: %+v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("mup() returned %d messages, want 1", len(msgs))
	}
	if msgs[0].IsIPv4 || msgs[0].IsNexthopIPv4 {
		t.Fatalf("IsIPv4 = %t, IsNexthopIPv4 = %t, want both false for an IPv6 withdrawal", msgs[0].IsIPv4, msgs[0].IsNexthopIPv4)
	}
	if msgs[0].Nexthop != "" {
		t.Fatalf("Nexthop = %q, want none on a withdrawal", msgs[0].Nexthop)
	}
}

// ISD and DSD routes carry the SRv6 SID in the Prefix-SID attribute; the
// SRv6 L3 Service TLV (type 5) must reach the message decoded, not as raw
// bytes. The attribute bytes are the type 5 vector of pkg/prefixsid.
func TestProducerMUPPrefixSID(t *testing.T) {
	update := mupUpdateWithPrefixSID()

	for _, tt := range []struct {
		name string
		nlri []byte
	}{
		{"ISD", []byte{
			0x01, 0x00, 0x01, 0x0c,
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
			0x18, 0x0a, 0x0a, 0x0a,
		}},
		{"DSD", []byte{
			0x01, 0x00, 0x02, 0x0c,
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
			0x0a, 0x0a, 0x0a, 0x01,
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			msgs, err := mupProducer().mup(mupReachNLRI(tt.nlri, false), AddPrefix, minimalPeerHeader(), update)
			if err != nil {
				t.Fatalf("mup() unexpected error: %+v", err)
			}
			m := msgs[0]
			if m.PrefixSID == nil || m.PrefixSID.SRv6L3Service == nil {
				t.Fatalf("PrefixSID = %+v, want a decoded SRv6 L3 Service", m.PrefixSID)
			}
			info, ok := m.PrefixSID.SRv6L3Service.SubTLVs[1][0].(*srv6.InformationSubTLV)
			if !ok {
				t.Fatalf("SubTLV 1 is %T, want *srv6.InformationSubTLV", m.PrefixSID.SRv6L3Service.SubTLVs[1][0])
			}
			if info.SID != "2001:0:5:3::" || info.EndpointBehavior != 17 {
				t.Fatalf("SID = %s, EndpointBehavior = %d, want 2001:0:5:3:: and 17", info.SID, info.EndpointBehavior)
			}

			b, err := json.Marshal(&m)
			if err != nil {
				t.Fatalf("json.Marshal() unexpected error: %+v", err)
			}
			var got map[string]any
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("json.Unmarshal() unexpected error: %+v", err)
			}
			psid, _ := got["prefix_sid"].(map[string]any)
			if _, ok := psid["srv6_l3_service"]; !ok {
				t.Fatalf("marshalled message lacks prefix_sid.srv6_l3_service: %s", b)
			}
		})
	}
}

func TestProducerMUPDiscoveryWithoutPrefixSIDIsSkipped(t *testing.T) {
	for _, tt := range []struct {
		name string
		nlri []byte
	}{
		{
			name: "ISD",
			nlri: []byte{
				0x01, 0x00, 0x01, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18, 0x0a, 0x0a, 0x0a,
			},
		},
		{
			name: "DSD",
			nlri: []byte{
				0x01, 0x00, 0x02, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x0a, 0x0a, 0x01,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			msgs, err := mupProducer().mup(mupReachNLRI(tt.nlri, false), AddPrefix, minimalPeerHeader(), minimalUpdate())
			if err != nil {
				t.Fatalf("mup() unexpected error: %+v", err)
			}
			if len(msgs) != 0 {
				t.Fatalf("mup() returned %d messages, want 0 for an announcement without Prefix-SID", len(msgs))
			}
		})
	}
}

func TestProducerMUPDiscoveryInvalidPrefixSIDIsSkipped(t *testing.T) {
	for _, tt := range []struct {
		name string
		attr []byte
	}{
		{name: "empty", attr: []byte{}},
		{name: "malformed", attr: []byte{0x05, 0x00, 0x00}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			update := minimalUpdate()
			update.PathAttributes = []bgp.PathAttribute{{AttributeType: 40, Attribute: tt.attr}}
			nlri := mupReachNLRI([]byte{
				0x01, 0x00, 0x01, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18, 0x0a, 0x0a, 0x0a,
			}, false)

			msgs, err := mupProducer().mup(nlri, AddPrefix, minimalPeerHeader(), update)
			if err != nil {
				t.Fatalf("mup() unexpected error: %+v", err)
			}
			if len(msgs) != 0 {
				t.Fatalf("mup() returned %d messages, want 0 for an announcement with %s Prefix-SID", len(msgs), tt.name)
			}
		})
	}
}

func TestProducerMUPWithdrawEOR(t *testing.T) {
	nlri := &bgp.MPUnReachNLRI{
		AddressFamilyID:    2,
		SubAddressFamilyID: 85,
	}

	msgs, err := mupProducer().mup(nlri, 1, minimalPeerHeader(), minimalUpdate())
	if err != nil {
		t.Fatalf("mup() unexpected error: %+v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("mup() returned %d messages, want 1", len(msgs))
	}
	if !msgs[0].IsEOR {
		t.Error("IsEOR = false, want true")
	}
	if msgs[0].Action != "del" {
		t.Errorf("Action = %s, want del", msgs[0].Action)
	}
	if msgs[0].IsIPv4 {
		t.Error("IsIPv4 = true, want false")
	}
	ensureMessageHash(&msgs[0])
	if msgs[0].Hash != "" {
		t.Errorf("Hash = %s, want none on an End-of-RIB", msgs[0].Hash)
	}
}

func TestProcessMPUpdateMUP(t *testing.T) {
	tests := []struct {
		name     string
		ipv6     bool
		splitAF  bool
		wantType int
	}{
		{name: "combined topic", wantType: bmp.MUPMsg},
		{name: "split IPv4 topic", splitAF: true, wantType: bmp.MUPV4Msg},
		{name: "split IPv6 topic", ipv6: true, splitAF: true, wantType: bmp.MUPV6Msg},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := []byte{
				0x01, 0x00, 0x02, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x0a, 0x0a, 0x01,
			}
			if tt.ipv6 {
				nlri = []byte{
					0x01, 0x00, 0x02, 0x18,
					0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
					0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				}
			}
			pub := &recordingPublisher{}
			p := &producer{
				publisher: pub,
				splitAF:   tt.splitAF,
			}
			p.processMPUpdate(mupReachNLRI(nlri, tt.ipv6), 0, minimalPeerHeader(), mupUpdateWithPrefixSID())
			if len(pub.msgs) != 1 {
				t.Fatalf("processMPUpdate() published %d messages, want 1", len(pub.msgs))
			}
			if pub.msgs[0].msgType != tt.wantType {
				t.Fatalf("processMPUpdate() published message type %d, want %d", pub.msgs[0].msgType, tt.wantType)
			}
			var got MUPPrefix
			if err := json.Unmarshal(pub.msgs[0].payload, &got); err != nil {
				t.Fatalf("json.Unmarshal() unexpected error: %+v", err)
			}
			if got.RouteType != 2 || got.VPNRD != "100:100" {
				t.Fatalf("published message = %+v, want a Direct Segment Discovery route for RD 100:100", got)
			}
		})
	}
}
