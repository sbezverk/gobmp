package message

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/ls"
)

// messageInterASTLV encodes a BGP-LS TLV for message-layer fixtures.
func messageInterASTLV(typ uint16, value []byte) []byte {
	b := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(value)))
	return append(b, value...)
}

// messageInterASLinkElement builds a complete NLRI type 7 element with dual-stack descriptors.
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

// decodedMessageInterASLink returns the decoded type 7 fixture for producer tests.
func decodedMessageInterASLink(t *testing.T) *base.InterASLinkNLRI {
	t.Helper()
	nlri, err := ls.UnmarshalLSNLRI71(messageInterASLinkElement(), false)
	if err != nil {
		t.Fatalf("UnmarshalLSNLRI71: %v", err)
	}
	return nlri.NLRI[0].LS.(*base.InterASLinkNLRI)
}

// TestProcessNLRI71InterASLink verifies an Add-Path advertisement is published with all structured fields.
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
	if got.InterASDomainKey == nil || got.InterASDomainKey.ASN != 65000 || got.InterASDomainKey.Identifier != 42 {
		t.Errorf("unexpected Inter-AS domain key: %+v", got.InterASDomainKey)
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

// TestProcessNLRI71InterASLinkWithdrawalWithAddPath verifies withdrawals retain their path identity.
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

// interASNLRI71Mock injects decoded SAFI 71 elements and decoder failures into dispatch tests.
type interASNLRI71Mock struct {
	*safi72MockNLRI
	nlri *ls.NLRI71
	err  error
}

// GetNLRI71 returns the configured result for the current dispatch test.
func (m *interASNLRI71Mock) GetNLRI71() (*ls.NLRI71, error) {
	return m.nlri, m.err
}

// TestProcessNLRI71InterASLinkFailures covers decode, type, operation, and publisher failure paths.
func TestProcessNLRI71InterASLinkFailures(t *testing.T) {
	ph := makePeerHeader(t, bmp.PeerType0, 0)
	update := &bgp.Update{}
	t.Run("decode", func(t *testing.T) {
		recorder := &recordingPublisher{}
		p := &producer{publisher: recorder}
		p.processNLRI71SubTypes(&interASNLRI71Mock{err: errPublishFailure}, 0, ph, update)
		if len(recorder.msgs) != 0 {
			t.Fatalf("published messages = %d, want 0", len(recorder.msgs))
		}
	})
	t.Run("type", func(t *testing.T) {
		recorder := &recordingPublisher{}
		p := &producer{publisher: recorder}
		p.processNLRI71SubTypes(&interASNLRI71Mock{nlri: &ls.NLRI71{NLRI: []ls.Element{{Type: 7, LS: []byte{1}}}}}, 0, ph, update)
		if len(recorder.msgs) != 0 {
			t.Fatalf("published messages = %d, want 0", len(recorder.msgs))
		}
	})
	t.Run("operation", func(t *testing.T) {
		recorder := &recordingPublisher{}
		p := &producer{publisher: recorder}
		p.processNLRI71SubTypes(&interASNLRI71Mock{nlri: &ls.NLRI71{NLRI: []ls.Element{{Type: 7, LS: decodedMessageInterASLink(t)}}}}, 2, ph, update)
		if len(recorder.msgs) != 0 {
			t.Fatalf("published messages = %d, want 0", len(recorder.msgs))
		}
	})
	t.Run("publish", func(t *testing.T) {
		publisher := &failingPublisher{}
		p := &producer{publisher: publisher}
		p.processNLRI71SubTypes(&interASNLRI71Mock{nlri: &ls.NLRI71{NLRI: []ls.Element{{Type: 7, LS: decodedMessageInterASLink(t)}}}}, 0, ph, update)
		if publisher.calls != 1 {
			t.Fatalf("publish calls = %d, want 1", publisher.calls)
		}
	})
}

// TestLSInterASLinkIPv6LocRIB verifies IPv6-only direct links and Loc-RIB metadata use fallback fields.
func TestLSInterASLinkIPv6LocRIB(t *testing.T) {
	link := decodedMessageInterASLink(t)
	link.ProtocolID = base.Direct
	delete(link.LocalNode.SubTLV, 1028)
	link.LocalNode.SubTLV[1029] = base.TLV{Type: 1029, Length: 16, Value: []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	delete(link.Link.LinkTLV, 271)
	link.Link.LinkTLV[272] = base.TLV{Type: 272, Length: 16, Value: []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}
	delete(link.Link.LinkTLV, 259)
	delete(link.Link.LinkTLV, 260)
	p := &producer{publisher: &recordingPublisher{}}
	msg, err := p.lsInterASLink(link, "2001:db8::ffff", 0, makePeerHeader(t, bmp.PeerType3, 0), &bgp.Update{}, true)
	if err != nil {
		t.Fatalf("lsInterASLink: %v", err)
	}
	if !msg.IsLocRIB || msg.AreaID != "0" {
		t.Errorf("is_loc_rib=%t area=%q", msg.IsLocRIB, msg.AreaID)
	}
	if msg.LocalLinkIP != "2001:db8:1::1" || msg.RemoteLinkIP != "2001:db8:1::2" {
		t.Errorf("IPv6 link addresses: local=%q remote=%q", msg.LocalLinkIP, msg.RemoteLinkIP)
	}
	if msg.LocalASBRIPv6 != "2001:db8::1" || msg.RemoteASBRIPv6 != "2001:db8::2" {
		t.Errorf("IPv6 ASBR IDs: local=%q remote=%q", msg.LocalASBRIPv6, msg.RemoteASBRIPv6)
	}
}
