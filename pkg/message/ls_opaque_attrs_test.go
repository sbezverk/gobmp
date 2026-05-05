package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// buildBGPLSAttrWithOpaque returns a BGP path attribute 29 payload carrying a
// single Opaque TLV of the given type+value. Wire format per RFC 9552 §5.3:
// Type (2B) | Length (2B) | Value (Length B).
func buildBGPLSAttrWithOpaque(tlvType uint16, value []byte) []byte {
	b := make([]byte, 4+len(value))
	b[0] = byte(tlvType >> 8)
	b[1] = byte(tlvType)
	b[2] = byte(len(value) >> 8)
	b[3] = byte(len(value))
	copy(b[4:], value)
	return b
}

func newPeerHeader() *bmp.PerPeerHeader {
	return &bmp.PerPeerHeader{
		PeerAS:            65000,
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         make([]byte, 4),
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     make([]byte, 8),
	}
}

// TestLSNode_PopulatesOpaqueNodeAttribute verifies the lsNode producer copies
// hex-encoded TLV 1025 values from the BGP-LS Attribute into LSNode.
func TestLSNode_PopulatesOpaqueNodeAttribute(t *testing.T) {
	attr29 := buildBGPLSAttrWithOpaque(1025, []byte{0xde, 0xad, 0xbe, 0xef})

	node := &base.NodeNLRI{
		ProtocolID: base.ISISL1,
		LocalNode:  &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
	}
	update := &bgp.Update{
		PathAttributes: []bgp.PathAttribute{
			{AttributeType: 29, AttributeLength: uint16(len(attr29)), Attribute: attr29},
		},
	}

	p := &producer{}
	msg, err := p.lsNode(node, "", 0, newPeerHeader(), update, false)
	if err != nil {
		t.Fatalf("lsNode() error: %v", err)
	}
	want := []string{"deadbeef"}
	if len(msg.OpaqueNodeAttribute) != len(want) || msg.OpaqueNodeAttribute[0] != want[0] {
		t.Errorf("OpaqueNodeAttribute = %v, want %v", msg.OpaqueNodeAttribute, want)
	}
}

// TestLSLink_PopulatesOpaqueLinkAttribute verifies the lsLink producer copies
// hex-encoded TLV 1097 values from the BGP-LS Attribute into LSLink.
func TestLSLink_PopulatesOpaqueLinkAttribute(t *testing.T) {
	attr29 := buildBGPLSAttrWithOpaque(1097, []byte{0x11, 0x22})

	link := &base.LinkNLRI{
		ProtocolID: base.ISISL1,
		LocalNode:  &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
		RemoteNode: &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
		Link:       &base.LinkDescriptor{LinkTLV: map[uint16]base.TLV{}},
	}
	update := &bgp.Update{
		PathAttributes: []bgp.PathAttribute{
			{AttributeType: 29, AttributeLength: uint16(len(attr29)), Attribute: attr29},
		},
	}

	p := &producer{}
	msg, err := p.lsLink(link, "", 0, newPeerHeader(), update, false)
	if err != nil {
		t.Fatalf("lsLink() error: %v", err)
	}
	want := []string{"1122"}
	if len(msg.OpaqueLinkAttribute) != len(want) || msg.OpaqueLinkAttribute[0] != want[0] {
		t.Errorf("OpaqueLinkAttribute = %v, want %v", msg.OpaqueLinkAttribute, want)
	}
}

// TestLSPrefix_PopulatesOpaquePrefixAttribute verifies the lsPrefix producer
// copies hex-encoded TLV 1157 values into LSPrefix.
func TestLSPrefix_PopulatesOpaquePrefixAttribute(t *testing.T) {
	attr29 := buildBGPLSAttrWithOpaque(1157, []byte{0xfe, 0xed})

	// PrefixDescriptor TLV 265 (IP Reachability) carrying 10.0.0.0/24 in
	// BGP NLRI format: length octet (0x18) + 3 prefix octets.
	prefixDesc := &base.PrefixDescriptor{
		PrefixTLV: map[uint16]base.TLV{
			265: {Type: 265, Length: 4, Value: []byte{0x18, 0x0a, 0x00, 0x00}},
		},
	}
	prfx := &base.PrefixNLRI{
		ProtocolID: base.ISISL1,
		LocalNode:  &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
		Prefix:     prefixDesc,
		IsIPv4:     true,
	}
	update := &bgp.Update{
		PathAttributes: []bgp.PathAttribute{
			{AttributeType: 29, AttributeLength: uint16(len(attr29)), Attribute: attr29},
		},
	}

	p := &producer{}
	msg, err := p.lsPrefix(prfx, "", 0, newPeerHeader(), update, true)
	if err != nil {
		t.Fatalf("lsPrefix() error: %v", err)
	}
	want := []string{"feed"}
	if len(msg.OpaquePrefixAttribute) != len(want) || msg.OpaquePrefixAttribute[0] != want[0] {
		t.Errorf("OpaquePrefixAttribute = %v, want %v", msg.OpaquePrefixAttribute, want)
	}
}

// TestLSNode_NoBGPLSAttributeLeavesOpaqueNil verifies that when the UPDATE has
// no path attribute 29, the LSNode.OpaqueNodeAttribute stays nil so the JSON
// field is omitted via omitempty.
func TestLSNode_NoBGPLSAttributeLeavesOpaqueNil(t *testing.T) {
	node := &base.NodeNLRI{
		ProtocolID: base.ISISL1,
		LocalNode:  &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
	}
	update := &bgp.Update{
		PathAttributes: []bgp.PathAttribute{},
	}
	p := &producer{}
	msg, err := p.lsNode(node, "", 0, newPeerHeader(), update, false)
	if err != nil {
		t.Fatalf("lsNode() error: %v", err)
	}
	if msg.OpaqueNodeAttribute != nil {
		t.Errorf("OpaqueNodeAttribute = %v, want nil", msg.OpaqueNodeAttribute)
	}
}
