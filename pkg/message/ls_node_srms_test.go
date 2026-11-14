package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
)

func TestLSNodeSRMSPreference(t *testing.T) {
	// RFC 9085 §2.1.5: TLV 1037 (0x040d) carries a one-octet preference.
	tests := []struct {
		name string
		wire []byte
		want string
	}{
		{
			name: "ordinary preference",
			wire: []byte{0x04, 0x0d, 0x00, 0x01, 0x80},
			want: "128",
		},
		{
			name: "zero preference",
			wire: []byte{0x04, 0x0d, 0x00, 0x01, 0x00},
			want: "0",
		},
		{
			name: "maximum preference",
			wire: []byte{0x04, 0x0d, 0x00, 0x01, 0xff},
			want: "255",
		},
		{
			name: "first well-formed preference wins",
			wire: []byte{
				0x04, 0x0d, 0x00, 0x02, 0x01, 0x02,
				0x04, 0x0d, 0x00, 0x01, 0x00,
				0x04, 0x0d, 0x00, 0x01, 0xff,
			},
			want: "0",
		},
		{name: "absent BGP-LS Attribute"},
		{
			name: "unrelated TLV",
			wire: []byte{0x04, 0x02, 0x00, 0x01, 'r'},
		},
		{
			name: "empty TLV",
			wire: []byte{0x04, 0x0d, 0x00, 0x00},
		},
		{
			name: "two-byte preference",
			wire: []byte{0x04, 0x0d, 0x00, 0x02, 0x01, 0x02},
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
			if got := string(fields["srms_preference"]); got != tt.want {
				t.Errorf("srms_preference = %q, want %q", got, tt.want)
			}
		})
	}
}
