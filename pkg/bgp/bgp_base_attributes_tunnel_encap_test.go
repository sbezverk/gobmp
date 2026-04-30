package bgp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/tunnel"
)

// buildPathAttr23 wraps a Tunnel Encapsulation Attribute value in the BGP
// path-attribute envelope per RFC 4271 §4.3 / RFC 9012 §2: flags 0xC0
// (optional transitive), type 23, 1-octet length.
func buildPathAttr23(value []byte) []byte {
	if len(value) > 255 {
		t := make([]byte, 4+len(value))
		t[0] = 0xD0 // optional transitive + extended length
		t[1] = 23
		t[2] = byte(len(value) >> 8)
		t[3] = byte(len(value))
		copy(t[4:], value)
		return t
	}
	t := make([]byte, 3+len(value))
	t[0] = 0xC0
	t[1] = 23
	t[2] = byte(len(value))
	copy(t[3:], value)
	return t
}

// TestBaseAttrs_TunnelEncap_WellFormed verifies that a parseable RFC 9012
// Tunnel Encapsulation Attribute populates BaseAttributes.TunnelEncap with the
// decoded TLV view, retains the raw bytes in TunnelEncapAttr (still consumed
// by pkg/message/srpolicy.go), and emits the new tunnel_encap JSON field.
func TestBaseAttrs_TunnelEncap_WellFormed(t *testing.T) {
	// Single SR Policy tunnel (type 13, length 6) with Preference sub-TLV
	// (type 12, length 4, value 0x00000064 = 100). Mirrors the existing
	// pkg/tunnel/tunnel_test.go fixture.
	tlv := []byte{0x00, 0x0d, 0x00, 0x06, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x64}
	raw := buildPathAttr23(tlv)

	ba, err := UnmarshalBGPBaseAttributes(raw)
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes() error: %v", err)
	}
	if ba.TunnelEncap == nil {
		t.Fatal("TunnelEncap is nil; want decoded TunnelEncapsulation")
	}
	if got := len(ba.TunnelEncap.Tunnels); got != 1 {
		t.Fatalf("TunnelEncap.Tunnels len = %d, want 1", got)
	}
	if got, want := ba.TunnelEncap.Tunnels[0].Type, uint16(tunnel.TypeSRPolicy); got != want {
		t.Errorf("tunnel type = %d, want %d", got, want)
	}
	if !bytes.Equal(ba.TunnelEncapAttr, tlv) {
		t.Errorf("TunnelEncapAttr = %x, want %x (raw bytes must remain for SR Policy consumer)", ba.TunnelEncapAttr, tlv)
	}

	out, err := json.Marshal(ba)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(out), `"tunnel_encap":`) {
		t.Errorf("json output missing tunnel_encap field: %s", out)
	}
}

// TestBaseAttrs_TunnelEncap_Malformed verifies that an unparseable RFC 9012
// attribute logs and leaves TunnelEncap nil, while TunnelEncapAttr still
// carries the raw bytes so the SR Policy consumer's own decoder can attempt
// recovery and the operator can inspect the payload off-line.
func TestBaseAttrs_TunnelEncap_Malformed(t *testing.T) {
	// Tunnel TLV header claims Length=100 but only 2 value bytes follow.
	tlv := []byte{0x00, 0x0d, 0x00, 0x64, 0xaa, 0xbb}
	raw := buildPathAttr23(tlv)

	ba, err := UnmarshalBGPBaseAttributes(raw)
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes() error: %v", err)
	}
	if ba.TunnelEncap != nil {
		t.Errorf("TunnelEncap = %+v, want nil for malformed attribute", ba.TunnelEncap)
	}
	if !bytes.Equal(ba.TunnelEncapAttr, tlv) {
		t.Errorf("TunnelEncapAttr = %x, want raw %x preserved on parse failure", ba.TunnelEncapAttr, tlv)
	}

	out, err := json.Marshal(ba)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(out), `"tunnel_encap":`) {
		t.Errorf("json output should omit tunnel_encap when nil: %s", out)
	}
}

// TestBaseAttrs_TunnelEncap_Absent verifies the omitempty guard: when no
// path attribute 23 is present, TunnelEncap stays nil and the JSON field is
// suppressed.
func TestBaseAttrs_TunnelEncap_Absent(t *testing.T) {
	// Origin only (type 1, IGP).
	raw := []byte{0x40, 0x01, 0x01, 0x00}
	ba, err := UnmarshalBGPBaseAttributes(raw)
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes() error: %v", err)
	}
	if ba.TunnelEncap != nil {
		t.Errorf("TunnelEncap = %+v, want nil when attribute 23 is absent", ba.TunnelEncap)
	}
	if len(ba.TunnelEncapAttr) != 0 {
		t.Errorf("TunnelEncapAttr len = %d, want 0", len(ba.TunnelEncapAttr))
	}

	out, err := json.Marshal(ba)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(out), `"tunnel_encap":`) {
		t.Errorf("json output should omit tunnel_encap when attribute absent: %s", out)
	}
}
