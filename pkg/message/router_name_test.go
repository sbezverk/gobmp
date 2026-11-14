package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

func initiation(name, descr string) *bmp.InitiationMessage {
	m := &bmp.InitiationMessage{}
	if descr != "" {
		m.TLV = append(m.TLV, bmp.InformationalTLV{InformationType: 1, InformationLength: uint16(len(descr)), Information: []byte(descr)})
	}
	if name != "" {
		m.TLV = append(m.TLV, bmp.InformationalTLV{InformationType: 2, InformationLength: uint16(len(name)), Information: []byte(name)})
	}
	return m
}

func lastPeerMessage(t *testing.T, rec *recordingPublisher, wantCount int) (PeerStateChange, map[string]json.RawMessage) {
	t.Helper()
	if len(rec.msgs) != wantCount {
		t.Fatalf("published %d messages, want %d", len(rec.msgs), wantCount)
	}
	raw := rec.msgs[len(rec.msgs)-1].payload
	var got PeerStateChange
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal published message failed: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("unmarshal published keys failed: %v", err)
	}
	return got, keys
}

func TestRouterNameFromInitiation(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	rec := p.publisher.(*recordingPublisher)
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)

	p.producingWorker(bmp.Message{Payload: initiation("switch1", "Arista vEOS")})
	if len(rec.msgs) != 0 {
		t.Fatalf("Initiation published %d messages, want 0", len(rec.msgs))
	}
	if len(p.prePeerUp) != 0 {
		t.Fatalf("Initiation was buffered pre-PeerUp")
	}

	p.producingWorker(bmp.Message{PeerHeader: ph, Payload: buildPeerUpMessage(t, "192.0.2.1")})
	got, _ := lastPeerMessage(t, rec, 1)
	if got.RouterName != "switch1" || got.RouterDescr != "Arista vEOS" {
		t.Errorf("peer up router_name=%q router_descr=%q", got.RouterName, got.RouterDescr)
	}

	p.producingWorker(bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 1}})
	got, _ = lastPeerMessage(t, rec, 2)
	if got.RouterName != "switch1" || got.RouterDescr != "Arista vEOS" {
		t.Errorf("peer down router_name=%q router_descr=%q", got.RouterName, got.RouterDescr)
	}

	// A later Initiation replaces both values, including dropping a missing TLV.
	p.producingWorker(bmp.Message{Payload: initiation("switch2", "")})
	p.producingWorker(bmp.Message{PeerHeader: ph, Payload: buildPeerUpMessage(t, "192.0.2.1")})
	got, keys := lastPeerMessage(t, rec, 3)
	if got.RouterName != "switch2" {
		t.Errorf("router_name=%q, want switch2", got.RouterName)
	}
	if _, ok := keys["router_descr"]; ok {
		t.Errorf("router_descr still present after replacement: %s", keys["router_descr"])
	}
}

func TestRouterNameTypedNilInitiation(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	rec := p.publisher.(*recordingPublisher)
	var nilInit *bmp.InitiationMessage
	p.producingWorker(bmp.Message{Payload: nilInit})
	if len(rec.msgs) != 0 {
		t.Fatalf("typed-nil Initiation published %d messages, want 0", len(rec.msgs))
	}
	p.producingWorker(bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, 0x00), Payload: buildPeerUpMessage(t, "192.0.2.1")})
	_, keys := lastPeerMessage(t, rec, 1)
	for _, k := range []string{"router_name", "router_descr"} {
		if _, ok := keys[k]; ok {
			t.Errorf("key %s present after typed-nil Initiation", k)
		}
	}
}

func TestRouterNameAbsentWithoutInitiation(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	rec := p.publisher.(*recordingPublisher)
	p.producingWorker(bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, 0x00), Payload: buildPeerUpMessage(t, "192.0.2.1")})
	_, keys := lastPeerMessage(t, rec, 1)
	for _, k := range []string{"router_name", "router_descr"} {
		if _, ok := keys[k]; ok {
			t.Errorf("key %s present without Initiation", k)
		}
	}
}
