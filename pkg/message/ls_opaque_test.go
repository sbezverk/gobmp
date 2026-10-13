package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/ls"
	"github.com/sbezverk/gobmp/pkg/te"
)

// testLSUnknownNLRI is a Link-State NLRI of unassigned type 99 with a 3-byte value.
var testLSUnknownNLRI = []byte{0x00, 0x63, 0x00, 0x03, 0xde, 0xad, 0xbe}

// testRD is a type 0 Route Distinguisher, 65000:1.
var testRD = []byte{0x00, 0x00, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x01}

// TestProcessMPUpdateLSOpaque decodes AFI 16388 MP_REACH_NLRI and
// MP_UNREACH_NLRI attributes from wire bytes and checks that an NLRI of an
// unknown type is published, not dropped. RFC 9552 Section 5.2: "An
// implementation MUST handle unknown Link-State NLRI types as opaque objects
// and MUST preserve and propagate them."
func TestProcessMPUpdateLSOpaque(t *testing.T) {
	malformedSequence := lsSPFTLV{typeID: bgpLSSPFSequenceNumberTLV, value: []byte{1}}
	tests := []struct {
		name       string
		safi       byte
		withdraw   bool
		nlri       []byte
		update     *bgp.Update
		wantTypes  []int
		wantAction string
		wantRD     string
	}{
		{name: "SAFI 80 add", safi: 80, nlri: testLSUnknownNLRI, update: testLSUpdate(testLSSequence()), wantTypes: []int{bmp.LSOpaqueMsg}, wantAction: "add"},
		{name: "SAFI 80 add next to a node", safi: 80, nlri: append(testLSNodeNLRI80(), testLSUnknownNLRI...), update: testLSUpdate(testLSSequence()), wantTypes: []int{bmp.LSNodeMsg, bmp.LSOpaqueMsg}, wantAction: "add"},
		// RFC 9815 Section 7.1: a malformed Sequence Number TLV withdraws the whole NLRI.
		{name: "SAFI 80 malformed attribute", safi: 80, nlri: testLSUnknownNLRI, update: testLSUpdate(malformedSequence), wantTypes: []int{bmp.LSOpaqueMsg}, wantAction: "del"},
		{name: "SAFI 80 withdraw", safi: 80, withdraw: true, nlri: testLSUnknownNLRI, update: testLSUpdate(testLSSequence()), wantTypes: []int{bmp.LSOpaqueMsg}, wantAction: "del"},
		{name: "SAFI 71 add", safi: 71, nlri: testLSUnknownNLRI, update: minimalUpdate(), wantTypes: []int{bmp.LSOpaqueMsg}, wantAction: "add"},
		{name: "SAFI 72 add", safi: 72, nlri: append(append([]byte{}, testRD...), testLSUnknownNLRI...), update: minimalUpdate(), wantTypes: []int{bmp.LSOpaqueMsg}, wantAction: "add", wantRD: "65000:1"},
		{name: "SAFI 72 withdraw", safi: 72, withdraw: true, nlri: append(append([]byte{}, testRD...), testLSUnknownNLRI...), update: minimalUpdate(), wantTypes: []int{bmp.LSOpaqueMsg}, wantAction: "del", wantRD: "65000:1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nlri bgp.MPNLRI
			var err error
			operation := AddPrefix
			if tt.withdraw {
				nlri, err = bgp.UnmarshalMPUnReachNLRI(append([]byte{0x40, 0x04, tt.safi}, tt.nlri...), map[int]bool{})
				operation = DelPrefix
			} else {
				reach := append([]byte{0x40, 0x04, tt.safi, 0x04, 0xc0, 0x00, 0x02, 0x02, 0x00}, tt.nlri...)
				nlri, err = bgp.UnmarshalMPReachNLRI(reach, false, map[int]bool{})
			}
			if err != nil {
				t.Fatalf("unmarshal MP NLRI error = %v", err)
			}

			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			p.processMPUpdate(nlri, operation, minimalPeerHeader(), tt.update)

			if len(publisher.msgs) != len(tt.wantTypes) {
				t.Fatalf("processMPUpdate() published %d messages, want %d", len(publisher.msgs), len(tt.wantTypes))
			}
			for i, want := range tt.wantTypes {
				if publisher.msgs[i].msgType != want {
					t.Errorf("message %d topic = %d, want %d", i, publisher.msgs[i].msgType, want)
				}
			}
			var got LSOpaque
			if err := json.Unmarshal(publisher.msgs[len(publisher.msgs)-1].payload, &got); err != nil {
				t.Fatalf("published LSOpaque JSON: %v", err)
			}
			if got.Action != tt.wantAction || got.SAFI != tt.safi || got.NLRIType != 99 || got.NLRI != "deadbe" || got.RD != tt.wantRD {
				t.Errorf("published LSOpaque = action %q SAFI %d type %d NLRI %q RD %q, want %q/%d/99/deadbe/%q",
					got.Action, got.SAFI, got.NLRIType, got.NLRI, got.RD, tt.wantAction, tt.safi, tt.wantRD)
			}
			if got.PeerASN != 65000 {
				t.Errorf("published LSOpaque PeerASN = %d, want 65000", got.PeerASN)
			}
		})
	}
}

// TestProcessMPUpdateLSOpaqueZeroLength checks that an unknown NLRI type with
// no value portion is published and does not drop the NLRI after it. RFC 9552
// Section 5.1: "a TLV with no value portion would have a length of zero".
func TestProcessMPUpdateLSOpaqueZeroLength(t *testing.T) {
	zeroLength := []byte{0x00, 0x64, 0x00, 0x00} // type 100, length 0
	tests := []struct {
		name   string
		safi   byte
		nlri   []byte
		update *bgp.Update
	}{
		{name: "SAFI 71", safi: 71, nlri: append(append([]byte{}, zeroLength...), testLSUnknownNLRI...), update: minimalUpdate()},
		{name: "SAFI 72", safi: 72, nlri: append(append(append(append([]byte{}, testRD...), zeroLength...), testRD...), testLSUnknownNLRI...), update: minimalUpdate()},
		{name: "SAFI 80", safi: 80, nlri: append(append([]byte{}, zeroLength...), testLSUnknownNLRI...), update: testLSUpdate(testLSSequence())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reach := append([]byte{0x40, 0x04, tt.safi, 0x04, 0xc0, 0x00, 0x02, 0x02, 0x00}, tt.nlri...)
			nlri, err := bgp.UnmarshalMPReachNLRI(reach, false, map[int]bool{})
			if err != nil {
				t.Fatalf("unmarshal MP NLRI error = %v", err)
			}
			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			p.processMPUpdate(nlri, AddPrefix, minimalPeerHeader(), tt.update)

			if len(publisher.msgs) != 2 {
				t.Fatalf("processMPUpdate() published %d messages, want 2", len(publisher.msgs))
			}
			want := []struct {
				nlriType uint16
				nlri     string
			}{{100, ""}, {99, "deadbe"}}
			for i, w := range want {
				if publisher.msgs[i].msgType != bmp.LSOpaqueMsg {
					t.Errorf("message %d topic = %d, want %d", i, publisher.msgs[i].msgType, bmp.LSOpaqueMsg)
				}
				var got LSOpaque
				if err := json.Unmarshal(publisher.msgs[i].payload, &got); err != nil {
					t.Fatalf("published LSOpaque JSON: %v", err)
				}
				if got.NLRIType != w.nlriType || got.NLRI != w.nlri || got.Action != "add" {
					t.Errorf("message %d = type %d NLRI %q action %q, want %d/%q/add", i, got.NLRIType, got.NLRI, got.Action, w.nlriType, w.nlri)
				}
			}
		})
	}
}

// TestProcessMPUpdateLSTEPolicyNotOpaque checks that a TE Policy NLRI (type
// 5), which gobmp decodes but does not publish, is not sent to the opaque
// topic as a decoded struct.
func TestProcessMPUpdateLSTEPolicyNotOpaque(t *testing.T) {
	publisher := &recordingPublisher{}
	p := &producer{publisher: publisher}
	p.processNLRI80SubTypes(
		lsSPFMockNLRI{nlri: &ls.NLRI71{NLRI: []ls.Element{{Type: 5, LS: &te.NLRI{}}}}},
		AddPrefix,
		minimalPeerHeader(),
		testLSUpdate(testLSSequence()),
	)
	if len(publisher.msgs) != 0 {
		t.Errorf("published %d messages, want 0", len(publisher.msgs))
	}
}

func TestProcessNLRI72SubTypesTEPolicyNotOpaque(t *testing.T) {
	publisher := &recordingPublisher{}
	p := &producer{publisher: publisher}
	mock := &safi72MockNLRI{nlri72: &ls.NLRI72{NLRI: []ls.VPNElement{{Type: 5, LS: &te.NLRI{}}}}}
	p.processNLRI72SubTypes(mock, AddPrefix, minimalPeerHeader(), minimalUpdate())
	if len(publisher.msgs) != 0 {
		t.Errorf("published %d messages, want 0", len(publisher.msgs))
	}
}

// TestLSOpaqueLocRIBFlags checks the RFC 9069 Loc-RIB peer flags on an opaque NLRI.
func TestLSOpaqueLocRIBFlags(t *testing.T) {
	p := &producer{}
	// RFC 9069 §4.2: the F flag (0x80) marks a filtered Loc-RIB.
	msg, err := p.lsOpaque(99, []byte{1}, 71, "", AddPrefix, makePeerHeader(t, bmp.PeerType3, 0x80))
	if err != nil {
		t.Fatalf("lsOpaque() error = %v", err)
	}
	if !msg.IsLocRIB || !msg.IsLocRIBFiltered || msg.IsAdjRIBInPost {
		t.Errorf("lsOpaque() flags = LocRIB %t LocRIBFiltered %t AdjRIBInPost %t, want true/true/false", msg.IsLocRIB, msg.IsLocRIBFiltered, msg.IsAdjRIBInPost)
	}
}

func TestLSOpaqueErrors(t *testing.T) {
	p := &producer{}
	if _, err := p.lsOpaque(99, []byte{1}, 71, "", 2, minimalPeerHeader()); err == nil {
		t.Error("lsOpaque() with operation 2: want error, got nil")
	}
	if _, err := p.lsOpaque(5, &base.NodeNLRI{}, 71, "", AddPrefix, minimalPeerHeader()); err == nil {
		t.Error("lsOpaque() with decoded value: want error, got nil")
	}
}
