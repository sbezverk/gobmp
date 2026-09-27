package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
)

// buildBGPLSAttrMulti concatenates several TLV encodings (via
// buildBGPLSAttrWithOpaque) into a single BGP-LS Attribute (type 29) payload.
func buildBGPLSAttrMulti(tlvs ...struct {
	Type  uint16
	Value []byte
}) []byte {
	var b []byte
	for _, tlv := range tlvs {
		b = append(b, buildBGPLSAttrWithOpaque(tlv.Type, tlv.Value)...)
	}
	return b
}

func rtIDAttr(tlvs ...struct {
	Type  uint16
	Value []byte
}) *bgp.Update {
	attr29 := buildBGPLSAttrMulti(tlvs...)
	return &bgp.Update{
		PathAttributes: []bgp.PathAttribute{
			{AttributeType: 29, AttributeLength: uint16(len(attr29)), Attribute: attr29},
		},
	}
}

var (
	v4Local = struct {
		Type  uint16
		Value []byte
	}{1028, []byte{10, 0, 0, 1}}
	v6Local = struct {
		Type  uint16
		Value []byte
	}{1029, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	v4Remote = struct {
		Type  uint16
		Value []byte
	}{1030, []byte{192, 168, 1, 1}}
	v6Remote = struct {
		Type  uint16
		Value []byte
	}{1031, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}
)

// TestLSNode_RouterID_ByTLVPresence covers RFC 9552 Section 5.3.1.4: TLVs
// 1028 (IPv4 local router-ID) and 1029 (IPv6 local router-ID) are chosen by
// TLV presence, not by the BMP peer's V-flag, which lsNode no longer takes.
// AF-3: an IPv6-only TLV used to be dropped for IPv4 peers and vice versa.
func TestLSNode_RouterID_ByTLVPresence(t *testing.T) {
	tests := []struct {
		name string
		attr *bgp.Update
		want string
	}{
		{"ipv4-only TLV", rtIDAttr(v4Local), "10.0.0.1"},
		{"ipv6-only TLV", rtIDAttr(v6Local), "2001:db8::1"},
		{"both TLVs present, prefer IPv4", rtIDAttr(v4Local, v6Local), "10.0.0.1"},
		{"neither TLV present", rtIDAttr(), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &base.NodeNLRI{
				ProtocolID: base.ISISL1,
				LocalNode:  &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
			}
			p := &producer{}
			msg, err := p.lsNode(node, "", 0, newPeerHeader(), tt.attr)
			if err != nil {
				t.Fatalf("lsNode() error: %v", err)
			}
			if msg.RouterID != tt.want {
				t.Errorf("RouterID = %q, want %q", msg.RouterID, tt.want)
			}
		})
	}
}

// TestLSLink_RouterID_ByTLVPresence covers RFC 9552 Section 5.3.2.1: TLVs
// 1028/1030 (IPv4) and 1029/1031 (IPv6) local/remote router-IDs are chosen by
// TLV presence, not by the BMP peer's V-flag.
func TestLSLink_RouterID_ByTLVPresence(t *testing.T) {
	tests := []struct {
		name       string
		attr       *bgp.Update
		wantLocal  string
		wantRemote string
	}{
		{"ipv4-only TLVs", rtIDAttr(v4Local, v4Remote), "10.0.0.1", "192.168.1.1"},
		{"ipv6-only TLVs", rtIDAttr(v6Local, v6Remote), "2001:db8::1", "2001:db8::2"},
		{"both present, prefer IPv4", rtIDAttr(v4Local, v6Local, v4Remote, v6Remote), "10.0.0.1", "192.168.1.1"},
		{"ipv4 local, ipv6-only remote", rtIDAttr(v4Local, v6Remote), "10.0.0.1", "2001:db8::2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := &base.LinkNLRI{
				ProtocolID: base.ISISL1,
				LocalNode:  &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
				RemoteNode: &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
				Link:       &base.LinkDescriptor{LinkTLV: map[uint16]base.TLV{}},
			}
			p := &producer{}
			msg, err := p.lsLink(link, "", 0, newPeerHeader(), tt.attr)
			if err != nil {
				t.Fatalf("lsLink() error: %v", err)
			}
			if msg.RouterID != tt.wantLocal {
				t.Errorf("RouterID = %q, want %q", msg.RouterID, tt.wantLocal)
			}
			if msg.RemoteRouterID != tt.wantRemote {
				t.Errorf("RemoteRouterID = %q, want %q", msg.RemoteRouterID, tt.wantRemote)
			}
		})
	}
}

// TestLSPrefix_RouterID_FallsBackToIPv6 covers the AF-3 hardening in
// pkg/message/ls-prefix.go: the router-ID TLV is chosen by which TLV
// (1028/1029) is present, not by the prefix NLRI type (ipv4 argument).
func TestLSPrefix_RouterID_FallsBackToIPv6(t *testing.T) {
	tests := []struct {
		name string
		ipv4 bool // prefix NLRI type - must not affect the router-ID result
		attr *bgp.Update
		want string
	}{
		{"ipv4 prefix, ipv6-only TLV", true, rtIDAttr(v6Local), "2001:db8::1"},
		{"ipv6 prefix, ipv4-only TLV", false, rtIDAttr(v4Local), "10.0.0.1"},
		{"ipv6 prefix, both present, prefer IPv4", false, rtIDAttr(v4Local, v6Local), "10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixDesc := &base.PrefixDescriptor{
				PrefixTLV: map[uint16]base.TLV{
					265: {Type: 265, Length: 4, Value: []byte{0x18, 0x0a, 0x00, 0x00}},
				},
			}
			prfx := &base.PrefixNLRI{
				ProtocolID: base.ISISL1,
				LocalNode:  &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
				Prefix:     prefixDesc,
				IsIPv4:     tt.ipv4,
			}
			p := &producer{}
			msg, err := p.lsPrefix(prfx, "", 0, newPeerHeader(), tt.attr, tt.ipv4)
			if err != nil {
				t.Fatalf("lsPrefix() error: %v", err)
			}
			if msg.RouterID != tt.want {
				t.Errorf("RouterID = %q, want %q", msg.RouterID, tt.want)
			}
		})
	}
}
