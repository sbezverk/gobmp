package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
)

func TestLSNodeSBFDDiscriminators(t *testing.T) {
	// RFC 9247 §3: TLV 1032 (0x0408) carries one or more 32-bit discriminators.
	tests := []struct {
		name string
		wire []byte
		want string
	}{
		{
			name: "single",
			wire: []byte{0x04, 0x08, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04},
			want: "[16909060]",
		},
		{
			name: "multiple in one TLV",
			wire: []byte{0x04, 0x08, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0xff, 0xff, 0xff, 0xff},
			want: "[16909060,4294967295]",
		},
		{
			name: "repeated with malformed TLV between",
			wire: []byte{
				0x04, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08,
				0x04, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x09, 0xff,
				0x04, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x07,
			},
			want: "[8,7]",
		},
		{name: "absent BGP-LS Attribute"},
		{
			name: "unrelated TLV",
			wire: []byte{0x04, 0x02, 0x00, 0x01, 'r'},
		},
		{
			name: "empty TLV",
			wire: []byte{0x04, 0x08, 0x00, 0x00},
		},
		{
			name: "short discriminator",
			wire: []byte{0x04, 0x08, 0x00, 0x03, 0x01, 0x02, 0x03},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &base.NodeNLRI{
				ProtocolID: base.ISISL1,
				LocalNode:  &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{}},
			}
			update := &bgp.Update{}
			if tt.wire != nil {
				update.PathAttributes = []bgp.PathAttribute{
					{AttributeType: 29, AttributeLength: uint16(len(tt.wire)), Attribute: tt.wire},
				}
			}
			msg, err := (&producer{}).lsNode(node, "", 0, newPeerHeader(), update)
			if err != nil {
				t.Fatalf("lsNode() error: %v", err)
			}
			raw, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("marshal LSNode: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("unmarshal LSNode fields: %v", err)
			}
			if got := string(fields["sbfd_discriminators"]); got != tt.want {
				t.Errorf("sbfd_discriminators = %q, want %q", got, tt.want)
			}
		})
	}
}
