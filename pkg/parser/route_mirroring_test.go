package parser

import (
	"encoding/binary"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

func routeMirrorParserPeerHeader() []byte {
	peer := make([]byte, bmp.PerPeerHeaderLength)
	peer[0] = byte(bmp.PeerType0)
	copy(peer[22:26], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint32(peer[26:30], 65000)
	copy(peer[30:34], []byte{10, 0, 0, 1})
	return peer
}

func routeMirrorParserBGPMessage(msgType byte, body []byte) []byte {
	pdu := make([]byte, 19+len(body))
	for i := 0; i < 16; i++ {
		pdu[i] = 0xff
	}
	binary.BigEndian.PutUint16(pdu[16:18], uint16(len(pdu)))
	pdu[18] = msgType
	copy(pdu[19:], body)
	return pdu
}

func routeMirrorParserBMPMessage(pdu []byte) []byte {
	body := make([]byte, 4+len(pdu))
	binary.BigEndian.PutUint16(body[:2], uint16(bmp.RouteMirrorBGPMsgTLV))
	binary.BigEndian.PutUint16(body[2:4], uint16(len(pdu)))
	copy(body[4:], pdu)
	msgLen := bmp.CommonHeaderLength + bmp.PerPeerHeaderLength + len(body)
	message := make([]byte, msgLen)
	message[0] = 3
	binary.BigEndian.PutUint32(message[1:5], uint32(msgLen))
	message[5] = bmp.RouteMirrorMsg
	copy(message[bmp.CommonHeaderLength:], routeMirrorParserPeerHeader())
	copy(message[bmp.CommonHeaderLength+bmp.PerPeerHeaderLength:], body)
	return message
}

func TestParsingWorkerRouteMirrorUpdate(t *testing.T) {
	// Empty UPDATE is the IPv4 End-of-RIB marker.
	pdu := routeMirrorParserBGPMessage(2, []byte{0, 0, 0, 0})
	queue := make(chan bmp.Message, 1)
	p := &parser{producerQueue: queue, config: &Config{SpeakerIP: "203.0.113.9"}}
	p.parsingWorker(routeMirrorParserBMPMessage(pdu))

	if len(queue) != 1 {
		t.Fatalf("queued %d messages, want 1", len(queue))
	}
	msg := <-queue
	rm, ok := msg.Payload.(*bmp.RouteMirror)
	if !ok || rm == nil {
		t.Fatalf("payload = %T, want non-nil *bmp.RouteMirror", msg.Payload)
	}
	if msg.SpeakerIP != "203.0.113.9" {
		t.Errorf("SpeakerIP = %q, want 203.0.113.9", msg.SpeakerIP)
	}
	if msg.PeerHeader == nil || msg.PeerHeader.PeerAS != 65000 || msg.PeerHeader.GetPeerAddrString() != "192.0.2.2" {
		t.Fatalf("PeerHeader = %+v, want peer AS 65000 at 192.0.2.2", msg.PeerHeader)
	}
	if update, err := rm.GetBGPUpdate(); err != nil || update == nil {
		t.Fatalf("GetBGPUpdate() = (%v, %v), want non-nil update", update, err)
	}
}

func TestParsingWorkerRouteMirrorNonUpdateContinues(t *testing.T) {
	keepalive := routeMirrorParserBMPMessage(routeMirrorParserBGPMessage(4, nil))
	peerDown := buildPeerDownMsg(routeMirrorParserPeerHeader(), 5, nil)
	input := append(keepalive, peerDown...)
	queue := make(chan bmp.Message, 2)
	p := &parser{producerQueue: queue, config: &Config{}}
	p.parsingWorker(input)

	if len(queue) != 1 {
		t.Fatalf("queued %d messages, want only the PeerDown following the non-UPDATE mirror", len(queue))
	}
	got := <-queue
	if down, ok := got.Payload.(*bmp.PeerDownMessage); !ok || down.Reason != 5 {
		t.Fatalf("payload = %#v, want PeerDown reason 5", got.Payload)
	}
}

func TestParsingWorkerRawRouteMirrorIncludesPeerHeader(t *testing.T) {
	pdu := routeMirrorParserBGPMessage(2, []byte{0, 0, 0, 0})
	queue := make(chan bmp.Message, 1)
	p := &parser{producerQueue: queue, config: &Config{EnableRawMode: true}}
	p.parsingWorker(routeMirrorParserBMPMessage(pdu))

	if len(queue) != 1 {
		t.Fatalf("queued %d messages, want 1", len(queue))
	}
	got := <-queue
	if _, ok := got.Payload.(*bmp.RawMessage); !ok {
		t.Fatalf("payload = %T, want *bmp.RawMessage", got.Payload)
	}
	if got.PeerHeader == nil || got.PeerHeader.PeerAS != 65000 {
		t.Fatalf("PeerHeader = %+v, want extracted peer header", got.PeerHeader)
	}
}
