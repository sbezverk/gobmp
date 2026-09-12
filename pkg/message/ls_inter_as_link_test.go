package message

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func messageInterASTLV(typ uint16, value []byte) []byte {
	b := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(value)))
	return append(b, value...)
}

func messageInterASLinkElement() []byte {
	local := append(messageInterASTLV(512, []byte{0, 0, 0xfd, 0xe8}), messageInterASTLV(514, []byte{0, 0, 0, 9})...)
	local = append(local, messageInterASTLV(515, []byte{10, 0, 0, 1})...)
	local = append(local, messageInterASTLV(1028, []byte{192, 0, 2, 1})...)
	links := append(messageInterASTLV(270, []byte{0, 0, 0xfd, 0xe9}), messageInterASTLV(271, []byte{192, 0, 2, 2})...)
	links = append(links, messageInterASTLV(258, []byte{0, 0, 0, 10, 0, 0, 0, 20})...)
	links = append(links, messageInterASTLV(259, []byte{198, 51, 100, 1})...)
	links = append(links, messageInterASTLV(260, []byte{198, 51, 100, 2})...)
	links = append(links, messageInterASTLV(261, []byte{0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})...)
	links = append(links, messageInterASTLV(262, []byte{0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})...)
	body := []byte{3, 0, 0, 0, 0, 0, 0, 0, 42}
	body = append(body, messageInterASTLV(256, local)...)
	body = append(body, links...)
	element := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint16(element[0:2], 7)
	binary.BigEndian.PutUint16(element[2:4], uint16(len(body)))
	return append(element, body...)
}

func TestProcessNLRI71InterASLink(t *testing.T) {
	pathNLRI := []byte{0, 0, 0, 77}
	pathNLRI = append(pathNLRI, messageInterASLinkElement()...)
	wire := []byte{0x40, 0x04, 71, 4, 203, 0, 113, 1, 0}
	wire = append(wire, pathNLRI...)
	nlri, err := bgp.UnmarshalMPReachNLRI(wire, false, map[int]bool{71: true})
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI: %v", err)
	}
	recorder := &recordingPublisher{}
	p := &producer{publisher: recorder}
	p.processMPUpdate(nlri, 0, makePeerHeader(t, bmp.PeerType0, 0), &bgp.Update{})
	if len(recorder.msgs) != 1 {
		t.Fatalf("published messages = %d, want 1", len(recorder.msgs))
	}
	if recorder.msgs[0].msgType != bmp.LSLinkMsg {
		t.Fatalf("message type = %d, want %d", recorder.msgs[0].msgType, bmp.LSLinkMsg)
	}
	var got LSLink
	if err := json.Unmarshal(recorder.msgs[0].payload, &got); err != nil {
		t.Fatalf("unmarshal published LSLink: %v", err)
	}
	if !got.IsInterAS {
		t.Error("is_inter_as is false")
	}
	if got.DomainID != 42 || got.LocalNodeASN != 65000 || got.RemoteNodeASN != 65001 {
		t.Errorf("unexpected domain/AS values: domain=%d local=%d remote=%d", got.DomainID, got.LocalNodeASN, got.RemoteNodeASN)
	}
	if got.LocalASBRIPv4 != "192.0.2.1" || got.RemoteASBRIPv4 != "192.0.2.2" {
		t.Errorf("unexpected ASBR IDs: local=%q remote=%q", got.LocalASBRIPv4, got.RemoteASBRIPv4)
	}
	if got.LocalLinkIP != "198.51.100.1" || got.RemoteLinkIP != "198.51.100.2" {
		t.Errorf("unexpected link addresses: local=%q remote=%q", got.LocalLinkIP, got.RemoteLinkIP)
	}
	if got.LocalLinkIPv4 != "198.51.100.1" || got.RemoteLinkIPv4 != "198.51.100.2" || got.LocalLinkIPv6 != "2001:db8:1::1" || got.RemoteLinkIPv6 != "2001:db8:1::2" {
		t.Errorf("unexpected dual-stack link addresses: local_v4=%q remote_v4=%q local_v6=%q remote_v6=%q", got.LocalLinkIPv4, got.RemoteLinkIPv4, got.LocalLinkIPv6, got.RemoteLinkIPv6)
	}
	if got.PathID != 77 {
		t.Errorf("path ID = %d, want 77", got.PathID)
	}
	if got.LocalLinkID != 10 || got.RemoteLinkID != 20 || got.AreaID != "9" {
		t.Errorf("unexpected link IDs/area: local=%d remote=%d area=%q", got.LocalLinkID, got.RemoteLinkID, got.AreaID)
	}
	if got.Nexthop != "203.0.113.1" || got.ProtocolID != 3 {
		t.Errorf("unexpected next hop/protocol: next_hop=%q protocol=%d", got.Nexthop, got.ProtocolID)
	}
}

func TestProcessNLRI71InterASLinkWithdrawalWithAddPath(t *testing.T) {
	wire := []byte{0x40, 0x04, 71, 0, 0, 0, 88}
	wire = append(wire, messageInterASLinkElement()...)
	nlri, err := bgp.UnmarshalMPUnReachNLRI(wire, map[int]bool{71: true})
	if err != nil {
		t.Fatalf("UnmarshalMPUnReachNLRI: %v", err)
	}
	recorder := &recordingPublisher{}
	p := &producer{publisher: recorder}
	p.processMPUpdate(nlri, 1, makePeerHeader(t, bmp.PeerType0, 0), &bgp.Update{})
	if len(recorder.msgs) != 1 {
		t.Fatalf("published messages = %d, want 1", len(recorder.msgs))
	}
	var got LSLink
	if err := json.Unmarshal(recorder.msgs[0].payload, &got); err != nil {
		t.Fatalf("unmarshal published LSLink: %v", err)
	}
	if got.Action != "del" || got.PathID != 88 || !got.IsInterAS {
		t.Errorf("withdrawal action=%q path_id=%d is_inter_as=%t", got.Action, got.PathID, got.IsInterAS)
	}
}
