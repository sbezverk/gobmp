package bmp_test

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func serializationPeer(t *testing.T, typ bmp.PeerType, flags byte) *bmp.PerPeerHeader {
	t.Helper()
	p := &bmp.PerPeerHeader{PeerType: typ, PeerDistinguisher: make([]byte, 8), PeerAddress: make([]byte, 16), PeerAS: 65000, PeerBGPID: []byte{192, 0, 2, 1}, PeerTimestamp: []byte{0, 0, 0, 1, 0, 0, 0, 2}}
	if typ != bmp.PeerType3 {
		copy(p.PeerAddress[12:], []byte{192, 0, 2, 2})
		if flags&0x80 != 0 {
			copy(p.PeerAddress, []byte{0x20, 1, 0xd, 0xb8})
		}
	} else {
		p.PeerDistinguisher = []byte{0, 3, 1, 2, 3, 4, 5, 6}
	}
	if err := p.SetFlags(flags); err != nil {
		t.Fatal(err)
	}
	return p
}

func serializationOpen() *bgp.OpenMessage {
	return &bgp.OpenMessage{Version: 4, MyAS: 65000, HoldTime: 90, BGPID: []byte{192, 0, 2, 1}, Capabilities: bgp.Capability{65: []*bgp.CapabilityData{{Value: []byte{0, 0, 0xfd, 0xe8}}}}}
}

func decodeSerializationFrame(t *testing.T, frame []byte) *bmp.Message {
	t.Helper()
	h, err := bmp.UnmarshalCommonHeader(frame)
	if err != nil {
		t.Fatal(err)
	}
	if int(h.MessageLength) != len(frame) {
		t.Fatalf("frame length %d != %d", h.MessageLength, len(frame))
	}
	m := &bmp.Message{}
	body := frame[6:]
	if h.MessageType <= bmp.PeerUpMsg {
		m.PeerHeader, err = bmp.UnmarshalPerPeerHeader(body)
		if err != nil {
			t.Fatal(err)
		}
		body = body[42:]
	}
	switch h.MessageType {
	case bmp.RouteMonitorMsg:
		as4 := true
		if m.PeerHeader.PeerType != bmp.PeerType3 {
			as4, _ = m.PeerHeader.Is4ByteASN()
		}
		m.Payload, err = bmp.UnmarshalBMPRouteMonitorMessageWithAS4Hint(body, as4)
	case bmp.StatsReportMsg:
		m.Payload, err = bmp.UnmarshalBMPStatsReportMessage(body)
	case bmp.PeerDownMsg:
		m.Payload, err = bmp.UnmarshalPeerDownMessage(body)
	case bmp.PeerUpMsg:
		m.Payload, err = bmp.UnmarshalPeerUpMessage(body, m.PeerHeader.IsRemotePeerIPv6())
	case bmp.InitiationMsg:
		m.Payload, err = bmp.UnmarshalInitiationMessage(body)
	case bmp.TerminationMsg:
		m.Payload, err = bmp.UnmarshalTerminationMessage(body)
	default:
		t.Fatalf("unexpected kind %d", h.MessageType)
	}
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSerializeTypedMessagesExternal(t *testing.T) {
	peer := serializationPeer(t, bmp.PeerType0, 0)
	cases := []struct {
		name    string
		typ     byte
		peer    *bmp.PerPeerHeader
		payload interface{}
	}{
		{"route EOR", bmp.RouteMonitorMsg, peer, &bmp.RouteMonitor{Update: &bgp.Update{}}},
		{"stats", bmp.StatsReportMsg, peer, &bmp.StatsReport{StatsCount: 999, StatsTLV: []bmp.InformationalTLV{{InformationType: 0, InformationLength: 99, Information: []byte{0, 0, 0, 3}}}}},
		{"peer down", bmp.PeerDownMsg, peer, &bmp.PeerDownMessage{Reason: 2, Data: []byte{0, 7}}},
		{"peer up", bmp.PeerUpMsg, peer, &bmp.PeerUpMessage{LocalAddress: append(make([]byte, 12), 192, 0, 2, 1), LocalPort: 179, RemotePort: 50000, SentOpen: serializationOpen(), ReceivedOpen: serializationOpen(), Information: []bmp.InformationalTLV{{InformationType: 3, Information: []byte("vrf")}}}},
		{"initiation", bmp.InitiationMsg, nil, &bmp.InitiationMessage{TLV: []bmp.InformationalTLV{{InformationType: 1, Information: []byte("router")}, {InformationType: 2, Information: []byte("name")}}}},
		{"termination", bmp.TerminationMsg, nil, &bmp.TerminationMessage{HasReason: true, Reason: 2, Strings: []string{"overload"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &bmp.Message{PeerHeader: tc.peer, Payload: tc.payload, SpeakerIP: "metadata"}
			frame, err := m.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if frame[5] != tc.typ {
				t.Fatalf("type=%d", frame[5])
			}
			parsed := decodeSerializationFrame(t, frame)
			again, err := parsed.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(frame, again) {
				t.Fatalf("unstable semantic round trip\n%x\n%x", frame, again)
			}
			if stats, ok := parsed.Payload.(*bmp.StatsReport); ok && stats.StatsCount != 1 {
				t.Fatal("count not derived")
			}
			if up, ok := parsed.Payload.(*bmp.PeerUpMessage); ok && len(up.SentOpen.Capabilities[65]) != 1 {
				t.Fatal("capability lost")
			}
		})
	}
}

func TestSerializeGoldenFrames(t *testing.T) {
	for _, tc := range []struct {
		payload interface{}
		want    []byte
	}{
		{&bmp.InitiationMessage{TLV: []bmp.InformationalTLV{{InformationType: 1}, {InformationType: 2}}}, []byte{3, 0, 0, 0, 14, 4, 0, 1, 0, 0, 0, 2, 0, 0}},
		{&bmp.InitiationMessage{TLV: []bmp.InformationalTLV{{InformationType: 1, Information: []byte("x")}, {InformationType: 2, Information: []byte("y")}}}, []byte{3, 0, 0, 0, 16, 4, 0, 1, 0, 1, 'x', 0, 2, 0, 1, 'y'}},
		{&bmp.TerminationMessage{HasReason: true, Reason: 0}, []byte{3, 0, 0, 0, 12, 5, 0, 1, 0, 2, 0, 0}},
	} {
		got, err := (&bmp.Message{Payload: tc.payload}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("got %x want %x", got, tc.want)
		}
	}
	got, err := (&bmp.StatsReport{StatsCount: 50}).Serialize()
	if err != nil || !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Fatalf("stats: %x %v", got, err)
	}
	got, err = (&bmp.RouteMonitor{Update: &bgp.Update{}}).Serialize()
	if err != nil || len(got) != 23 || !bytes.Equal(got[16:], []byte{0, 23, 2, 0, 0, 0, 0}) {
		t.Fatalf("EOR: %x %v", got, err)
	}
}

func TestSerializePeerModesExternal(t *testing.T) {
	for _, typ := range []bmp.PeerType{0, 1, 2, 3} {
		for _, flags := range []byte{0, 0x80, 0xf0} {
			if typ == 3 && flags == 0xf0 {
				continue
			}
			p := serializationPeer(t, typ, flags)
			before := *p
			b, err := p.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if b[1] != flags {
				t.Fatalf("flags %x", b[1])
			}
			if !reflect.DeepEqual(before, *p) {
				t.Fatal("receiver mutated")
			}
			q, err := bmp.UnmarshalPerPeerHeader(b)
			if err != nil {
				t.Fatal(err)
			}
			again, err := q.Serialize()
			if err != nil || !bytes.Equal(b, again) {
				t.Fatalf("peer round trip: %v", err)
			}
			// In particular, the locally defined type-3 distinguisher is not an RD.
			if typ == 3 && !bytes.Equal(b[2:10], []byte{0, 3, 1, 2, 3, 4, 5, 6}) {
				t.Fatal("Loc-RIB distinguisher changed")
			}
			b[2] ^= 0xff
			if !reflect.DeepEqual(before, *p) {
				t.Fatal("output aliases receiver")
			}
		}
	}
	p := serializationPeer(t, 3, 0x80)
	tlv, err := (bmp.InformationalTLV{InformationType: 3, Information: []byte("vrf")}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := (&bmp.Message{PeerHeader: p, Payload: &bmp.PeerDownMessage{Reason: 6, Data: tlv}}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	decodeSerializationFrame(t, frame)
	// RFC 9069 section 5.2: a fabricated AS4 OPEN repeated in both slots.
	up := &bmp.PeerUpMessage{LocalAddress: make([]byte, 16), SentOpen: serializationOpen(), ReceivedOpen: serializationOpen()}
	frame, err = (&bmp.Message{PeerHeader: p, Payload: up}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	decodeSerializationFrame(t, frame)
	// ASN width is carried unchanged. Type-0 A=1 permits two-byte AS_PATH;
	// Loc-RIB must instead use four-byte encoding (RFC 9069 section 5.4.1).
	u := &bgp.Update{PathAttributes: []bgp.PathAttribute{{AttributeTypeFlags: 0x40, AttributeType: 2, Attribute: []byte{2, 1, 0xfd, 0xe8}}}}
	if _, err = (&bmp.Message{PeerHeader: serializationPeer(t, 0, 0x20), Payload: &bmp.RouteMonitor{Update: u}}).Serialize(); err != nil {
		t.Fatal(err)
	}
	if _, err = (&bmp.Message{PeerHeader: p, Payload: &bmp.RouteMonitor{Update: u}}).Serialize(); err == nil {
		t.Fatal("Loc-RIB accepted AS2")
	}
}

func TestSerializeErrorsExternal(t *testing.T) {
	p := serializationPeer(t, 0, 0)
	badMicro := serializationPeer(t, 0, 0)
	binary.BigEndian.PutUint32(badMicro.PeerTimestamp[4:], 1000000)
	badPadding := serializationPeer(t, 0, 0)
	badPadding.PeerAddress[0] = 1
	cases := []func() ([]byte, error){
		func() ([]byte, error) { return (*bmp.Message)(nil).Serialize() },
		func() ([]byte, error) { return (&bmp.Message{}).Serialize() },
		func() ([]byte, error) { return (&bmp.Message{Payload: (*bmp.PeerUpMessage)(nil)}).Serialize() },
		func() ([]byte, error) {
			return (&bmp.Message{Payload: &bmp.RawMessage{Msg: []byte{3, 0, 0, 0, 6, 4}}}).Serialize()
		},
		func() ([]byte, error) {
			return (&bmp.Message{Payload: &bmp.RouteMonitor{Update: &bgp.Update{}}}).Serialize()
		},
		func() ([]byte, error) {
			return (&bmp.Message{PeerHeader: p, Payload: &bmp.InitiationMessage{TLV: []bmp.InformationalTLV{{InformationType: 1}, {InformationType: 2}}}}).Serialize()
		},
		func() ([]byte, error) { return (*bmp.PerPeerHeader)(nil).Serialize() },
		func() ([]byte, error) { return (&bmp.PerPeerHeader{}).Serialize() },
		badMicro.Serialize, badPadding.Serialize,
		func() ([]byte, error) { return (bmp.InformationalTLV{Information: make([]byte, 65536)}).Serialize() },
		func() ([]byte, error) { return (*bmp.InitiationMessage)(nil).Serialize() },
		func() ([]byte, error) { return (*bmp.StatsReport)(nil).Serialize() },
		func() ([]byte, error) { return (*bmp.TerminationMessage)(nil).Serialize() },
		func() ([]byte, error) { return (&bmp.TerminationMessage{}).Serialize() },
		func() ([]byte, error) { return (*bmp.PeerDownMessage)(nil).Serialize() },
		func() ([]byte, error) { return (&bmp.PeerDownMessage{}).Serialize() },
		func() ([]byte, error) { return (&bmp.PeerDownMessage{Reason: 1, Data: []byte{0}}).Serialize() },
		func() ([]byte, error) { return (&bmp.PeerDownMessage{Reason: 2}).Serialize() },
		func() ([]byte, error) { return (&bmp.PeerDownMessage{Reason: 4, Data: []byte{0}}).Serialize() },
		func() ([]byte, error) { return (&bmp.PeerDownMessage{Reason: 6, Data: []byte{0}}).Serialize() },
		func() ([]byte, error) {
			return (&bmp.Message{PeerHeader: serializationPeer(t, 3, 0), Payload: &bmp.PeerDownMessage{Reason: 4}}).Serialize()
		},
		func() ([]byte, error) { return (*bmp.RouteMonitor)(nil).Serialize() },
		func() ([]byte, error) { return (&bmp.RouteMonitor{}).Serialize() },
		func() ([]byte, error) { return (*bmp.PeerUpMessage)(nil).Serialize() },
		func() ([]byte, error) { return (&bmp.PeerUpMessage{LocalAddress: make([]byte, 16)}).Serialize() },
	}
	for i, f := range cases {
		if b, err := f(); err == nil || b != nil {
			t.Errorf("case %d: %x, %v", i, b, err)
		}
	}
	if err := p.SetFlags(1); err == nil {
		t.Fatal("accepted reserved flag")
	}
	if err := serializationPeer(t, 3, 0).SetFlags(0x40); err == nil {
		t.Fatal("accepted L for Loc-RIB")
	}
	if err := (*bmp.PerPeerHeader)(nil).SetFlags(0); err == nil {
		t.Fatal("nil setter")
	}
}

func TestSerializeOwnsBodyAndDerivesLengths(t *testing.T) {
	tlv := bmp.InformationalTLV{InformationType: 65000, InformationLength: 99, Information: []byte{1, 2, 3}}
	b, err := tlv.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(b[2:4]) != 3 || tlv.InformationLength != 99 {
		t.Fatal("length contract")
	}
	b[4] = 9
	if tlv.Information[0] != 1 {
		t.Fatal("TLV aliases input")
	}
	down := &bmp.PeerDownMessage{Reason: 2, Data: []byte{0, 1}}
	b, err = down.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	b[1] = 9
	if down.Data[0] != 0 {
		t.Fatal("PeerDown aliases input")
	}
}

func TestSerializeRejectsMalformedStatistics(t *testing.T) {
	for _, kind := range []uint16{0, 7, 9, 11, 14, 16} {
		if _, err := (&bmp.StatsReport{StatsTLV: []bmp.InformationalTLV{{InformationType: kind, Information: []byte{1}}}}).Serialize(); err == nil {
			t.Fatalf("accepted malformed statistic %d", kind)
		}
	}
	// Unknown statistics are opaque, preserving forward compatibility.
	if _, err := (&bmp.StatsReport{StatsTLV: []bmp.InformationalTLV{{InformationType: 65000, Information: []byte{1}}}}).Serialize(); err != nil {
		t.Fatal(err)
	}
}

func TestSerializeInitiationRequiredTLVs(t *testing.T) {
	for _, tlvs := range [][]bmp.InformationalTLV{nil, {}, {{InformationType: 1}}, {{InformationType: 2}}, {{InformationType: 65000}}} {
		p := &bmp.InitiationMessage{TLV: tlvs}
		if body, err := p.Serialize(); err == nil || body != nil {
			t.Fatalf("accepted missing required TLV: %+v", tlvs)
		}
		if frame, err := (&bmp.Message{Payload: p}).Serialize(); err == nil || frame != nil {
			t.Fatalf("assembled missing required TLV: %+v", tlvs)
		}
	}
	// Presence is required; values and duplicate occurrences are not restricted.
	// Additional/unknown TLVs retain their position and bytes.
	tlvs := []bmp.InformationalTLV{{InformationType: 65000, Information: []byte{1, 2}}, {InformationType: 2}, {InformationType: 1, Information: []byte("descr")}, {InformationType: 1}}
	frame, err := (&bmp.Message{Payload: &bmp.InitiationMessage{TLV: tlvs}}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed := decodeSerializationFrame(t, frame).Payload.(*bmp.InitiationMessage)
	if len(parsed.TLV) != len(tlvs) {
		t.Fatal("additional/duplicate TLVs lost")
	}
	for i, tlv := range parsed.TLV {
		if tlv.InformationType != tlvs[i].InformationType || !bytes.Equal(tlv.Information, tlvs[i].Information) {
			t.Fatalf("TLV %d changed", i)
		}
	}
}

func TestSerializeOutPrePolicyWireRoundTrip(t *testing.T) {
	// RFC 8671 section 5.2: a real wire representation can carry an empty
	// NEXT_HOP before outbound policy supplies it. Do not turn it into 0.0.0.0.
	raw := []byte{0, 0, 0, 10, 0x40, 1, 1, 0, 0x40, 2, 0, 0x40, 3, 0, 24, 192, 0, 2}
	u, err := bgp.UnmarshalBGPUpdateWithAS4Hint(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := u.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(standalone[19:], raw) {
		t.Fatalf("UPDATE raw bytes changed: %x", standalone[19:])
	}
	body, err := (&bmp.RouteMonitor{Update: u}).Serialize()
	if err != nil || !bytes.Equal(body, standalone) {
		t.Fatalf("standalone RouteMonitor: %v", err)
	}
	for _, typ := range []bmp.PeerType{0, 1, 2} {
		for _, flags := range []byte{0x10, 0x30} {
			frame, err := (&bmp.Message{PeerHeader: serializationPeer(t, typ, flags), Payload: &bmp.RouteMonitor{Update: u}}).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(frame[6+42+19:], raw) {
				t.Fatal("full frame changed raw UPDATE")
			}
			parsed := decodeSerializationFrame(t, frame)
			again, err := parsed.Serialize()
			if err != nil || !bytes.Equal(frame, again) {
				t.Fatalf("parsed Out-pre roundtrip: %v", err)
			}
		}
	}
}

func TestSerializePlaceholdersRequireOutPrePolicy(t *testing.T) {
	for _, placeholder := range []byte{1, 3, 5} {
		for _, as4 := range []bool{false, true} {
			asPath := []byte{2, 1, 0xfd, 0xe8}
			if as4 {
				asPath = []byte{2, 1, 0, 0, 0xfd, 0xe8}
			}
			attrs := []bgp.PathAttribute{{AttributeTypeFlags: 0x40, AttributeType: 1, Attribute: []byte{0}}, {AttributeTypeFlags: 0x40, AttributeType: 2, Attribute: asPath}, {AttributeTypeFlags: 0x40, AttributeType: 3, Attribute: []byte{192, 0, 2, 1}}, {AttributeTypeFlags: 0x40, AttributeType: 5, Attribute: []byte{0, 0, 0, 100}}}
			for i := range attrs {
				if attrs[i].AttributeType == placeholder {
					attrs[i].Attribute = nil
				}
			}
			u := &bgp.Update{PathAttributes: attrs}
			standalone, err := u.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			body, err := (&bmp.RouteMonitor{Update: u}).Serialize()
			if err != nil || !bytes.Equal(standalone, body) {
				t.Fatalf("standalone placeholder %d: %v", placeholder, err)
			}
			wrongFlags := byte(0x10)
			if as4 {
				wrongFlags |= 0x20
			}
			if _, err := (&bmp.Message{PeerHeader: serializationPeer(t, 0, wrongFlags), Payload: &bmp.RouteMonitor{Update: u}}).Serialize(); err == nil {
				t.Fatal("placeholder bypassed ASN-width validation")
			}
			for _, typ := range []bmp.PeerType{0, 1, 2, 3} {
				for _, view := range []byte{0, 0x40, 0x10, 0x50} {
					if typ == 3 && view != 0 {
						continue
					}
					flags := view
					if typ != 3 && !as4 {
						flags |= 0x20
					}
					m := &bmp.Message{PeerHeader: serializationPeer(t, typ, flags), Payload: &bmp.RouteMonitor{Update: u}}
					frame, err := m.Serialize()
					allowed := typ != 3 && view == 0x10
					if !allowed {
						if err == nil || frame != nil {
							t.Fatalf("placeholder %d accepted peer %d flags %#x", placeholder, typ, flags)
						}
						continue
					}
					if err != nil {
						t.Fatalf("placeholder %d AS4=%t: %v", placeholder, as4, err)
					}
					parsed := decodeSerializationFrame(t, frame).Payload.(*bmp.RouteMonitor)
					if !bytes.Equal(frame[48:], standalone) {
						t.Fatal("placeholder or ASN wire attributes changed")
					}
					for i, a := range parsed.Update.PathAttributes {
						want := u.PathAttributes[i]
						if a.AttributeType != want.AttributeType || a.AttributeTypeFlags != want.AttributeTypeFlags || !bytes.Equal(a.Attribute, want.Attribute) {
							t.Fatalf("raw attribute %d changed", i)
						}
					}
				}
			}
		}
	}
	// Removing attribute values does not authorize malformed nonzero encodings.
	for _, a := range []bgp.PathAttribute{{AttributeTypeFlags: 0x40, AttributeType: 1, Attribute: []byte{3}}, {AttributeTypeFlags: 0x40, AttributeType: 1, Attribute: []byte{0, 0}}, {AttributeTypeFlags: 0x40, AttributeType: 3, Attribute: []byte{0}}, {AttributeTypeFlags: 0x40, AttributeType: 5, Attribute: []byte{0}}} {
		u := &bgp.Update{PathAttributes: []bgp.PathAttribute{a}}
		if _, err := u.Serialize(); err == nil {
			t.Fatalf("accepted malformed nonzero attribute %d", a.AttributeType)
		}
	}
}
