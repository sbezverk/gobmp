package message

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func routeMirrorLSUpdatePDU() []byte {
	// AFI 16388 / SAFI 71 MP_REACH carrying a valid BGP-LS node NLRI.
	nlri := []byte{
		0x00, 0x01, 0x00, 0x1d,
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x10,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8,
		0x02, 0x04, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
	}
	mpReach := []byte{
		0x40, 0x04, 0x47, // AFI 16388, SAFI 71
		0x04, 0xc0, 0x00, 0x02, 0x02, // IPv4 next hop
		0x00, // reserved
	}
	mpReach = append(mpReach, nlri...)
	attrs := []byte{
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe8, // 4-byte AS_PATH, AS_SEQUENCE 65000
		0x80, 0x0e, byte(len(mpReach)), // MP_REACH_NLRI
	}
	attrs = append(attrs, mpReach...)
	body := []byte{0, 0}
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(body, attrs...)
	pdu := make([]byte, 19+len(body))
	for i := 0; i < 16; i++ {
		pdu[i] = 0xff
	}
	binary.BigEndian.PutUint16(pdu[16:18], uint16(len(pdu)))
	pdu[18] = 2 // UPDATE
	copy(pdu[19:], body)
	return pdu
}

func routeMirrorPayloadFromPDU(t *testing.T, pdu []byte) *bmp.RouteMirror {
	t.Helper()
	wire := make([]byte, 4+len(pdu))
	binary.BigEndian.PutUint16(wire[:2], uint16(bmp.RouteMirrorBGPMsgTLV))
	binary.BigEndian.PutUint16(wire[2:4], uint16(len(pdu)))
	copy(wire[4:], pdu)
	rm, err := bmp.UnmarshalBMPRouteMirrorMessage(wire)
	if err != nil {
		t.Fatalf("UnmarshalBMPRouteMirrorMessage() error = %v", err)
	}
	return rm
}

func TestProducerDecodesRouteMirrorBGPLinkStateUpdate(t *testing.T) {
	publisher := &recordingPublisher{}
	p := NewProducer(publisher, false).(*producer)
	close(p.speakerReady) // exercise the RouteMirror producer path after Peer Up
	peer := makePeerHeader(t, bmp.PeerType0, 0)

	p.producingWorker(bmp.Message{
		PeerHeader: peer,
		Payload:    routeMirrorPayloadFromPDU(t, routeMirrorLSUpdatePDU()),
	})

	if len(publisher.msgs) != 1 {
		t.Fatalf("published %d messages, want one BGP-LS node", len(publisher.msgs))
	}
	if publisher.msgs[0].msgType != bmp.LSNodeMsg {
		t.Fatalf("message type = %d, want LSNodeMsg (%d)", publisher.msgs[0].msgType, bmp.LSNodeMsg)
	}
	var got LSNode
	if err := json.Unmarshal(publisher.msgs[0].payload, &got); err != nil {
		t.Fatalf("unmarshal published LSNode: %v", err)
	}
	if got.Action != "add" || got.ProtocolID != base.Direct || got.ASN != 65000 {
		t.Fatalf("decoded LSNode = action %q protocol %d ASN %d, want add/%d/65000", got.Action, got.ProtocolID, got.ASN, base.Direct)
	}
}

func routeMirrorUpdatePDU(withdrawn, attrs, nlri []byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, uint16(len(withdrawn)))
	body = append(body, withdrawn...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(body, attrs...)
	body = append(body, nlri...)
	pdu := make([]byte, 19+len(body))
	for i := 0; i < 16; i++ {
		pdu[i] = 0xff
	}
	binary.BigEndian.PutUint16(pdu[16:18], uint16(len(pdu)))
	pdu[18] = 2 // UPDATE
	copy(pdu[19:], body)
	return pdu
}

func routeMirrorWire(pdu []byte, info ...uint16) []byte {
	var wire []byte
	for _, code := range info {
		wire = binary.BigEndian.AppendUint16(wire, uint16(bmp.RouteMirrorInfoTLV))
		wire = binary.BigEndian.AppendUint16(wire, 2)
		wire = binary.BigEndian.AppendUint16(wire, code)
	}
	if pdu != nil {
		wire = binary.BigEndian.AppendUint16(wire, uint16(bmp.RouteMirrorBGPMsgTLV))
		wire = binary.BigEndian.AppendUint16(wire, uint16(len(pdu)))
		wire = append(wire, pdu...)
	}
	return wire
}

func TestRouteMirrorErroredPDUTreatAsWithdraw(t *testing.T) {
	base := []byte{
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe8, // AS_PATH 65000
	}
	v4Attrs := append(append([]byte{}, base...), 0x40, 0x03, 0x04, 192, 0, 2, 1) // NEXT_HOP
	v4NLRI := []byte{24, 198, 51, 100}                                           // 198.51.100.0/24
	mpReach := []byte{0x00, 0x02, 0x01, 0x10}                                    // AFI 2, SAFI 1, next hop length 16
	mpReach = append(mpReach, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
	mpReach = append(mpReach, 0x00, 48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01) // reserved, 2001:db8:1::/48
	v6Attrs := append(append([]byte{}, base...), 0x80, 0x0e, byte(len(mpReach)))
	v6Attrs = append(v6Attrs, mpReach...)
	v4Withdrawn := []byte{24, 203, 0, 113} // 203.0.113.0/24

	tests := []struct {
		name string
		wire []byte
		want []string // action per published message
	}{
		{"errored IPv4 NLRI", routeMirrorWire(routeMirrorUpdatePDU(nil, v4Attrs, v4NLRI), 0), []string{"del"}},
		{"errored IPv6 MP_REACH", routeMirrorWire(routeMirrorUpdatePDU(nil, v6Attrs, nil), 0), []string{"del"}},
		{"errored IPv4 withdrawn and NLRI", routeMirrorWire(routeMirrorUpdatePDU(v4Withdrawn, v4Attrs, v4NLRI), 0), []string{"del", "del"}},
		{"errored empty UPDATE is not End-of-RIB", routeMirrorWire(routeMirrorUpdatePDU(nil, nil, nil), 0), nil},
		{"BGP message only IPv4", routeMirrorWire(routeMirrorUpdatePDU(nil, v4Attrs, v4NLRI)), []string{"add"}},
		{"BGP message only IPv6", routeMirrorWire(routeMirrorUpdatePDU(nil, v6Attrs, nil)), []string{"add"}},
		{"messages lost without BGP message", routeMirrorWire(nil, 1), nil},
		{"errored without BGP message", routeMirrorWire(nil, 0), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm, err := bmp.UnmarshalBMPRouteMirrorMessage(tt.wire)
			if err != nil {
				t.Fatalf("UnmarshalBMPRouteMirrorMessage() error = %v", err)
			}
			publisher := &recordingPublisher{}
			p := NewProducer(publisher, false).(*producer)
			p.produceRouteMessage(bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, 0), Payload: rm})
			var got []string
			for _, m := range publisher.msgs {
				var up UnicastPrefix
				if err := json.Unmarshal(m.payload, &up); err != nil {
					t.Fatalf("unmarshal published message: %v", err)
				}
				got = append(got, up.Action)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("actions = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("actions = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestPrePeerUpRouteMirrorByteAccounting(t *testing.T) {
	payload := &bmp.RouteMirror{TLVs: []bmp.TLV{{
		Type:  bmp.RouteMirrorBGPMsgTLV,
		Value: make([]byte, maxPrePeerUpBytes),
	}}}
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	p.producingWorker(bmp.Message{
		PeerHeader: makePeerHeader(t, bmp.PeerType0, 0),
		Payload:    payload,
	})
	if len(p.prePeerUp) != 0 || p.prePeerUpBytes != 0 {
		t.Fatalf("oversized mirror retained: messages=%d bytes=%d", len(p.prePeerUp), p.prePeerUpBytes)
	}
}

func TestProduceRouteMessageRejectsInvalidPayloads(t *testing.T) {
	peer := makePeerHeader(t, bmp.PeerType0, 0)
	var nilRouteMonitor *bmp.RouteMonitor
	var nilRouteMirror *bmp.RouteMirror
	tests := []struct {
		name string
		msg  bmp.Message
	}{
		{name: "missing peer header", msg: bmp.Message{Payload: &bmp.RouteMonitor{}}},
		{name: "nil route monitor", msg: bmp.Message{PeerHeader: peer, Payload: nilRouteMonitor}},
		{name: "route monitor without update", msg: bmp.Message{PeerHeader: peer, Payload: &bmp.RouteMonitor{}}},
		{name: "nil route mirror", msg: bmp.Message{PeerHeader: peer, Payload: nilRouteMirror}},
		{name: "route mirror without BGP update", msg: bmp.Message{PeerHeader: peer, Payload: &bmp.RouteMirror{}}},
		{name: "unsupported payload", msg: bmp.Message{PeerHeader: peer, Payload: &bmp.StatsReport{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := &recordingPublisher{}
			p := NewProducer(publisher, false).(*producer)
			p.produceRouteMessage(tt.msg)
			if len(publisher.msgs) != 0 {
				t.Fatalf("published %d messages for invalid route input, want 0", len(publisher.msgs))
			}
		})
	}
}
