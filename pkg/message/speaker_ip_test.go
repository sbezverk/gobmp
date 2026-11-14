package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestSpeakerIPOnPeerMessages(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	rec := p.publisher.(*recordingPublisher)
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)

	// The BGP local address (192.0.2.1) differs from the TCP source (198.51.100.7).
	p.producingWorker(bmp.Message{SpeakerIP: "198.51.100.7", PeerHeader: ph, Payload: buildPeerUpMessage(t, "192.0.2.1")})
	got, _ := lastPeerMessage(t, rec, 1)
	if got.SpeakerIP != "198.51.100.7" {
		t.Errorf("peer up speaker_ip=%q, want 198.51.100.7", got.SpeakerIP)
	}
	if got.RouterIP != "192.0.2.1" {
		t.Errorf("peer up router_ip=%q, want 192.0.2.1", got.RouterIP)
	}

	p.producingWorker(bmp.Message{SpeakerIP: "198.51.100.7", PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 1}})
	got, _ = lastPeerMessage(t, rec, 2)
	if got.SpeakerIP != "198.51.100.7" {
		t.Errorf("peer down speaker_ip=%q, want 198.51.100.7", got.SpeakerIP)
	}
}

func TestSpeakerIPAbsentWhenUnknown(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	rec := p.publisher.(*recordingPublisher)
	p.producingWorker(bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, 0x00), Payload: buildPeerUpMessage(t, "192.0.2.1")})
	_, keys := lastPeerMessage(t, rec, 1)
	if _, ok := keys["speaker_ip"]; ok {
		t.Errorf("speaker_ip present without a speaker address: %s", keys["speaker_ip"])
	}
}
