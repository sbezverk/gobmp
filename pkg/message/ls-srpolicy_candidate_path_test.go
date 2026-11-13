package message

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/ls"
	"github.com/sbezverk/gobmp/pkg/srpolicycp"
)

func messageSRPolicyStateTLV(typ uint16, value []byte) []byte {
	b := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(value)))
	return append(b, value...)
}

func messageSRPolicyCandidatePathNLRI() *srpolicycp.SrPolicyCandidatePathNLRI {
	return &srpolicycp.SrPolicyCandidatePathNLRI{
		ProtocolID: base.SR,
		Identifier: []byte{0, 0, 0, 0, 0, 0, 0, 42},
		LocalNode: &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{
			1028: {Type: 1028, Length: 4, Value: []byte{192, 0, 2, 1}},
		}},
		LocalNodeHash: "local-node-hash",
		Descriptor:    &srpolicycp.SRPCPDescriptor{},
	}
}

func messageSRPolicyStateUpdate() *bgp.Update {
	value := messageSRPolicyStateTLV(1213, []byte("blue-policy"))
	return &bgp.Update{PathAttributes: []bgp.PathAttribute{{
		AttributeType: 29,
		Attribute:     value,
	}}}
}

func messageSRPolicyStateUpdateWithSegmentList() *bgp.Update {
	label := make([]byte, 4)
	binary.BigEndian.PutUint32(label, uint32(16001)<<12)
	segment := []byte{1, 0, 0xe0, 0}
	segment = append(segment, label...)
	segment = append(segment, 0) // Type 1 Algorithm descriptor.
	segmentList := make([]byte, 12)
	binary.BigEndian.PutUint32(segmentList[8:12], 100)
	segmentList = append(segmentList, messageSRPolicyStateTLV(1206, segment)...)
	value := messageSRPolicyStateTLV(1213, []byte("blue-policy"))
	value = append(value, messageSRPolicyStateTLV(1205, segmentList)...)
	return &bgp.Update{PathAttributes: []bgp.PathAttribute{{
		AttributeType: 29,
		Attribute:     value,
	}}}
}

func TestLSSrPolicyCandidatePathIncludesPolicyState(t *testing.T) {
	ph := makePeerHeader(t, bmp.PeerType0, 0)
	p := &producer{}

	msg, err := p.lsSSRPolicyCandidatePath(messageSRPolicyCandidatePathNLRI(), "192.0.2.9", 0, ph, messageSRPolicyStateUpdate())
	if err != nil {
		t.Fatalf("lsSSRPolicyCandidatePath() error = %v", err)
	}
	if msg.SAFI != 71 || msg.RD != "" {
		t.Errorf("SAFI/RD = %d/%q, want 71/empty", msg.SAFI, msg.RD)
	}
	if msg.PolicyState == nil || msg.PolicyState.PolicyName == nil || msg.PolicyState.PolicyName.Name != "blue-policy" {
		t.Fatalf("PolicyState = %+v, want policy name blue-policy", msg.PolicyState)
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var decoded LSSrPolicyCandidatePath
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded.PolicyState == nil || decoded.PolicyState.PolicyName == nil || decoded.PolicyState.PolicyName.Name != "blue-policy" {
		t.Errorf("decoded PolicyState = %+v, want policy name blue-policy", decoded.PolicyState)
	}
}

func TestLSSrPolicyCandidatePathIncludesSegmentListWhenAFlagClear(t *testing.T) {
	ph := makePeerHeader(t, bmp.PeerType0, 0)
	p := &producer{}

	msg, err := p.lsSSRPolicyCandidatePath(messageSRPolicyCandidatePathNLRI(), "192.0.2.9", 0, ph, messageSRPolicyStateUpdateWithSegmentList())
	if err != nil {
		t.Fatalf("lsSSRPolicyCandidatePath() error = %v", err)
	}
	if msg.PolicyState == nil || len(msg.PolicyState.SegmentLists) != 1 {
		t.Fatalf("PolicyState = %+v, want one segment list", msg.PolicyState)
	}
	if len(msg.PolicyState.SegmentLists[0].SubTLV) != 1 {
		t.Fatalf("segment-list sub-TLVs = %d, want one segment", len(msg.PolicyState.SegmentLists[0].SubTLV))
	}
	segment, ok := msg.PolicyState.SegmentLists[0].SubTLV[0].(*bgpls.SRSegment)
	if !ok {
		t.Fatalf("segment type = %T, want *bgpls.SRSegment", msg.PolicyState.SegmentLists[0].SubTLV[0])
	}
	if segment.FlagA || segment.SegmentDescriptor == nil {
		t.Fatalf("segment flags/descriptor = A:%t descriptor:%#v, want A:false and descriptor", segment.FlagA, segment.SegmentDescriptor)
	}
}

func TestLSSrPolicyCandidatePathValidationAndVariants(t *testing.T) {
	valid := messageSRPolicyCandidatePathNLRI()
	ph := makePeerHeader(t, bmp.PeerType3, 0)

	tests := []struct {
		name string
		call func() error
	}{
		{name: "nil producer", call: func() error {
			var p *producer
			_, err := p.lsSSRPolicyCandidatePath(valid, "192.0.2.9", 0, ph, nil)
			return err
		}},
		{name: "nil peer header", call: func() error {
			_, err := (&producer{}).lsSSRPolicyCandidatePath(valid, "192.0.2.9", 0, nil, nil)
			return err
		}},
		{name: "nil NLRI", call: func() error {
			_, err := (&producer{}).lsSSRPolicyCandidatePath(nil, "192.0.2.9", 0, ph, nil)
			return err
		}},
		{name: "short identifier", call: func() error {
			copy := *valid
			copy.Identifier = []byte{1}
			_, err := (&producer{}).lsSSRPolicyCandidatePath(&copy, "192.0.2.9", 0, ph, nil)
			return err
		}},
		{name: "nil local node", call: func() error {
			copy := *valid
			copy.LocalNode = nil
			_, err := (&producer{}).lsSSRPolicyCandidatePath(&copy, "192.0.2.9", 0, ph, nil)
			return err
		}},
		{name: "nil descriptor", call: func() error {
			copy := *valid
			copy.Descriptor = nil
			_, err := (&producer{}).lsSSRPolicyCandidatePath(&copy, "192.0.2.9", 0, ph, nil)
			return err
		}},
		{name: "unknown operation", call: func() error {
			_, err := (&producer{}).lsSSRPolicyCandidatePath(valid, "192.0.2.9", 7, ph, nil)
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	ipv6 := messageSRPolicyCandidatePathNLRI()
	ipv6.LocalNode = &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{
		1029: {Type: 1029, Length: 16, Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}}
	msg, err := (&producer{}).lsSSRPolicyCandidatePath(ipv6, "2001:db8::9", 1, ph, nil)
	if err != nil {
		t.Fatalf("IPv6/delete candidate path error = %v", err)
	}
	if msg.Action != "del" || msg.LocalIPv6RouterID != "2001:db8::1" || msg.PolicyState != nil {
		t.Fatalf("IPv6/delete message = %+v, want del, IPv6 router ID, and no policy state", msg)
	}

	msg, err = (&producer{}).lsSSRPolicyCandidatePath(valid, "192.0.2.9", 0, ph, &bgp.Update{})
	if err != nil {
		t.Fatalf("malformed update should not reject base message: %v", err)
	}
	if msg.PolicyState != nil {
		t.Fatalf("malformed update produced policy state: %+v", msg.PolicyState)
	}

	badState := &bgp.Update{PathAttributes: []bgp.PathAttribute{{
		AttributeType: 29,
		Attribute:     messageSRPolicyStateTLV(bgpls.SRPolicyNameType, nil),
	}}}
	msg, err = (&producer{}).lsSSRPolicyCandidatePath(valid, "192.0.2.9", 0, ph, badState)
	if err != nil {
		t.Fatalf("malformed policy state should not reject base message: %v", err)
	}
	if msg.PolicyState != nil {
		t.Fatalf("malformed policy state produced policy state: %+v", msg.PolicyState)
	}
}

func TestProcessNLRI72SubTypes_SRPolicyCandidatePath(t *testing.T) {
	rd, err := base.MakeRD([]byte{0, 0, 0, 100, 0, 0, 0, 7})
	if err != nil {
		t.Fatalf("MakeRD() error = %v", err)
	}
	nlri := messageSRPolicyCandidatePathNLRI()
	rec := &recordingPublisher{}
	p := &producer{publisher: rec}
	mock := &safi72MockNLRI{nlri72: &ls.NLRI72{NLRI: []ls.VPNElement{{
		RD:     rd,
		Type:   5,
		Length: 8,
		LS:     nlri,
	}}}}
	p.processNLRI72SubTypes(mock, 0, makePeerHeader(t, bmp.PeerType0, 0), messageSRPolicyStateUpdate())

	if len(rec.msgs) != 1 {
		t.Fatalf("published messages = %d, want 1", len(rec.msgs))
	}
	if rec.msgs[0].msgType != bmp.SRPolicyCandidatePathMsg {
		t.Fatalf("message type = %d, want %d", rec.msgs[0].msgType, bmp.SRPolicyCandidatePathMsg)
	}
	var msg LSSrPolicyCandidatePath
	if err := json.Unmarshal(rec.msgs[0].payload, &msg); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if msg.SAFI != 72 || msg.RD != "100:7" {
		t.Errorf("SAFI/RD = %d/%q, want 72/100:7", msg.SAFI, msg.RD)
	}
	if msg.PolicyState == nil || msg.PolicyState.PolicyName == nil || msg.PolicyState.PolicyName.Name != "blue-policy" {
		t.Errorf("PolicyState = %+v, want policy name blue-policy", msg.PolicyState)
	}
}

func TestProcessNLRI71SubTypes_SRPolicyCandidatePath(t *testing.T) {
	rec := &recordingPublisher{}
	p := &producer{publisher: rec}
	p.processNLRI71SubTypes(&interASNLRI71Mock{
		nlri: &ls.NLRI71{NLRI: []ls.Element{{Type: 5, PathID: 9, LS: messageSRPolicyCandidatePathNLRI()}}},
	}, 0, makePeerHeader(t, bmp.PeerType0, 0), messageSRPolicyStateUpdate(), false)

	if len(rec.msgs) != 1 {
		t.Fatalf("published messages = %d, want 1", len(rec.msgs))
	}
	if rec.msgs[0].msgType != bmp.SRPolicyCandidatePathMsg {
		t.Fatalf("message type = %d, want %d", rec.msgs[0].msgType, bmp.SRPolicyCandidatePathMsg)
	}
	var msg LSSrPolicyCandidatePath
	if err := json.Unmarshal(rec.msgs[0].payload, &msg); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if msg.SAFI != 71 || msg.RD != "" || msg.PathID != 9 {
		t.Fatalf("SAFI/RD/path ID = %d/%q/%d, want 71/empty/9", msg.SAFI, msg.RD, msg.PathID)
	}
}
