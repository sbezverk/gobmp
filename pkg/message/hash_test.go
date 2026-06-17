package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestMarshalAndPublishPopulatesUnicastHash(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	rec := p.publisher.(*recordingPublisher)

	msg := &UnicastPrefix{
		Action:     "add",
		RouterHash: "router",
		PeerHash:   "peer",
		Prefix:     "198.51.100.0",
		PrefixLen:  24,
		IsIPv4:     true,
		PeerIP:     "10.0.0.2",
		Nexthop:    "10.0.0.1",
	}
	if err := p.marshalAndPublish(&msg, bmp.UnicastPrefixMsg, []byte(msg.RouterHash)); err != nil {
		t.Fatalf("marshalAndPublish failed: %v", err)
	}

	var got UnicastPrefix
	if err := json.Unmarshal(rec.msgs[0].payload, &got); err != nil {
		t.Fatalf("unmarshal published message failed: %v", err)
	}
	if got.Hash == "" {
		t.Fatal("Hash is empty")
	}
}

func TestUnicastHashStableAcrossAddDelAttributes(t *testing.T) {
	add := &UnicastPrefix{
		Action:         "add",
		RouterHash:     "router",
		PeerHash:       "peer",
		Prefix:         "198.51.100.0",
		PrefixLen:      24,
		IsIPv4:         true,
		BaseAttributes: &bgp.BaseAttributes{Nexthop: "10.0.0.1"},
		Timestamp:      "2026-06-17T08:00:00Z",
	}
	del := &UnicastPrefix{
		Action:         "del",
		RouterHash:     "router",
		PeerHash:       "peer",
		Prefix:         "198.51.100.0",
		PrefixLen:      24,
		IsIPv4:         true,
		BaseAttributes: &bgp.BaseAttributes{},
		Timestamp:      "2026-06-17T08:01:00Z",
	}

	setUnicastPrefixHash(add)
	setUnicastPrefixHash(del)
	if add.Hash == "" || del.Hash == "" {
		t.Fatalf("hashes must be non-empty: add=%q del=%q", add.Hash, del.Hash)
	}
	if add.Hash != del.Hash {
		t.Fatalf("hash changed across add/del for same route identity: add=%q del=%q", add.Hash, del.Hash)
	}
}

func TestMarshalAndPublishPopulatesL3VPNHash(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	rec := p.publisher.(*recordingPublisher)

	msg := L3VPNPrefix{
		Action:     "add",
		RouterHash: "router",
		PeerHash:   "peer",
		VPNRD:      "50123:100",
		VPNRDType:  0,
		Prefix:     "10.255.100.0",
		PrefixLen:  24,
		IsIPv4:     true,
		Labels:     []uint32{1000},
	}
	if err := p.marshalAndPublish(&msg, bmp.L3VPNMsg, []byte(msg.RouterHash)); err != nil {
		t.Fatalf("marshalAndPublish failed: %v", err)
	}

	var got L3VPNPrefix
	if err := json.Unmarshal(rec.msgs[0].payload, &got); err != nil {
		t.Fatalf("unmarshal published message failed: %v", err)
	}
	if got.Hash == "" {
		t.Fatal("Hash is empty")
	}
}

func TestMarshalAndPublishPopulatesPeerStateHash(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	rec := p.publisher.(*recordingPublisher)

	msg := PeerStateChange{
		Action:      "add",
		RouterHash:  "router",
		RemoteBGPID: "10.0.0.1",
		RemoteIP:    "10.0.0.2",
		RemoteASN:   65000,
		PeerType:    uint8(bmp.PeerType0),
	}
	if err := p.marshalAndPublish(&msg, bmp.PeerStateChangeMsg, []byte(msg.RouterHash)); err != nil {
		t.Fatalf("marshalAndPublish failed: %v", err)
	}

	var got PeerStateChange
	if err := json.Unmarshal(rec.msgs[0].payload, &got); err != nil {
		t.Fatalf("unmarshal published message failed: %v", err)
	}
	if got.Hash == "" {
		t.Fatal("Hash is empty")
	}
}
