package ls

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// This literal is independent of the fixture encoder: RFC 9552 §5.2 Figure 6
// places Type/Length before RD, and Length 47 includes RD(8) + Node body(39).
var nodeVPNWire = []byte{
	0x00, 0x01, 0x00, 0x2f,
	0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x1a,
	0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8,
	0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
}

func TestUnmarshalLSNLRI72Wire(t *testing.T) {
	got, err := UnmarshalLSNLRI72(nodeVPNWire, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.NLRI) != 1 {
		t.Fatalf("NLRI count = %d, want one Node", len(got.NLRI))
	}
	el := got.NLRI[0]
	node, ok := el.LS.(*base.NodeNLRI)
	if !ok || el.Type != 1 || el.Length != 47 || el.RD.String() != "100:1" {
		t.Fatalf("element = %+v, want Node type 1, length 47, RD 100:1", el)
	}
	if node.GetNodeASN() != 65000 || node.GetIdentifier() != 0 {
		t.Errorf("Node ASN/identifier = %d/%d, want 65000/0", node.GetNodeASN(), node.GetIdentifier())
	}
	for cut := 0; cut < len(nodeVPNWire); cut++ {
		t.Run(fmt.Sprintf("truncated at %d", cut), func(t *testing.T) {
			if partial, err := UnmarshalLSNLRI72(nodeVPNWire[:cut], false); err == nil || partial != nil {
				t.Fatalf("truncated Node = %+v, %v; want nil, error", partial, err)
			}
		})
	}
}

func TestUnmarshalLSNLRI72OpaqueRD(t *testing.T) {
	tests := []struct {
		name string
		rd   []byte
		want string
	}{
		{"type 0", []byte{0, 0, 0, 100, 0, 0, 0, 1}, "100:1"},
		{"type 1", []byte{0, 1, 192, 0, 2, 1, 0, 100}, "192.0.2.1:100"},
		{"type 2", []byte{0, 2, 0, 1, 0, 0, 0, 100}, "65536:100"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Type 7 remains unsupported in SAFI 72 and must stay opaque even
			// though SAFI 71 has a typed decoder (RFC 9552 §5.2).
			input := append([]byte{0, 0, 0, 7, 0, 7, 0, 11}, tt.rd...)
			input = append(input, 0xab, 0xcd, 0xef)
			input = append(input, 0, 0, 0, 9, 0, 7, 0, 8)
			input = append(input, tt.rd...)
			got, err := UnmarshalLSNLRI72(input, true)
			if err != nil || len(got.NLRI) != 2 {
				t.Fatalf("decode = %+v, %v; want two opaque elements", got, err)
			}
			for i, want := range []struct {
				length uint16
				pathID uint32
				body   []byte
			}{{11, 7, []byte{0xab, 0xcd, 0xef}}, {8, 9, nil}} {
				el := got.NLRI[i]
				raw, ok := el.LS.([]byte)
				if !ok || el.Type != 7 || el.Length != want.length || el.PathID != want.pathID || el.RD.String() != tt.want || !bytes.Equal(raw, want.body) {
					t.Errorf("element %d = %+v, want type 7 length %d PathID %d RD %s body %x", i, el, want.length, want.pathID, tt.want, want.body)
				}
			}
			clear(input)
			if raw := got.NLRI[0].LS.([]byte); !bytes.Equal(raw, []byte{0xab, 0xcd, 0xef}) || got.NLRI[0].RD.String() != tt.want {
				t.Errorf("decoded body/RD changed after input mutation: %+v", got.NLRI[0])
			}
		})
	}
}

func TestUnmarshalLSNLRI72InvalidFraming(t *testing.T) {
	validOpaque := []byte{0, 99, 0, 8, 0, 0, 0, 100, 0, 0, 0, 1}
	type testCase struct {
		name   string
		input  []byte
		pathID bool
		want   string
	}
	tests := []testCase{
		{"PathID", []byte{0, 0, 0}, true, "need 4 bytes"},
		{"header after PathID", []byte{0, 0, 0, 7, 0, 99, 0}, true, "need 4 bytes for TLV header"},
		{"value", []byte{0, 99, 0, 9, 0, 0, 0, 100, 0, 0, 0, 1}, false, "need 9 bytes, have 8"},
		{"RD type", []byte{0, 99, 0, 8, 0, 3, 0, 100, 0, 0, 0, 1}, false, "invalid rd type 3"},
		{"tail after valid element", append(bytes.Clone(validOpaque), 0), false, "need 4 bytes for TLV header"},
		// The following NLRI must not supply the missing Node Identifier.
		{"body isolated from neighbor", append([]byte{0, 1, 0, 9, 0, 0, 0, 100, 0, 0, 0, 1, 2}, validOpaque...), false, "need 8 bytes, have 0"},
		{"legacy RD first", append(rdType0(100, 1), 0, 99, 0, 0), false, "truncated"},
	}
	for length := byte(0); length < 8; length++ {
		tests = append(tests, testCase{fmt.Sprintf("length %d below RD size", length), []byte{0, 99, 0, length}, false, "need 8 bytes for Route Distinguisher"})
	}
	for typ := byte(1); typ <= 6; typ++ {
		input := bytes.Clone(validOpaque)
		input[1] = typ
		tests = append(tests, testCase{fmt.Sprintf("empty known type %d", typ), input, false, ""})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLSNLRI72(tt.input, tt.pathID)
			if err == nil || got != nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("decode = %+v, %v; want nil, error containing %q", got, err, tt.want)
			}
		})
	}
}
