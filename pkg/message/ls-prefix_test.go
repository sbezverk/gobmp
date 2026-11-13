package message

import (
	"encoding/json"
	"reflect"
	"strconv"

	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"

	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/sr"
)

func TestRoundTripLSPrefix(t *testing.T) {
	original := &LSPrefix{
		Key:        "Key",
		ID:         "ID",
		Rev:        "Rev",
		ProtocolID: base.ISISL1,
		PrefixAttrTLVs: &bgpls.PrefixAttrTLVs{
			LSPrefixSID: []*sr.PrefixSIDTLV{
				{
					Flags: &sr.ISISFlags{
						RFlag: false,
						NFlag: true,
						PFlag: false,
						EFlag: false,
						VFlag: false,
						LFlag: false,
					},
					Algorithm: 129,
					SID:       20007,
				},
			},
		},
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("TestRoundTripLSPrefix Marshal failed with error: %+v but supposed to succeed", err)
	}

	recovered := &LSPrefix{}
	if err := json.Unmarshal(b, recovered); err != nil {
		t.Fatalf("TestRoundTripLSPrefix Unmarshal failed with error: %+v but supposed to succeed", err)
	}
	if !reflect.DeepEqual(original, recovered) {
		t.Logf("Differences: %+v", deep.Equal(original, recovered))
		t.Fatalf("TestRoundTripLSPrefix failed as original %+v does not match recovered: %+v", *original, *recovered)
	}
}

func TestLSPrefix_OSPFForwardingAddress(t *testing.T) {
	tests := []struct {
		name  string
		proto base.ProtoID
		value []byte
		want  string
	}{
		{"IPv4", base.OSPFv2, []byte{192, 0, 2, 9}, "192.0.2.9"},
		{"IPv6", base.OSPFv3, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, "2001:db8::9"},
		{"absent", base.OSPFv2, nil, ""},
		{"invalid address length", base.OSPFv2, []byte{192, 0, 2}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prfx := &base.PrefixNLRI{
				ProtocolID: tt.proto,
				LocalNode:  &base.NodeDescriptor{},
				Prefix: &base.PrefixDescriptor{
					PrefixTLV: map[uint16]base.TLV{
						265: {Type: 265, Length: 1, Value: []byte{0}},
					},
				},
			}
			update := &bgp.Update{}
			if tt.value != nil {
				// RFC 9552 §5.3.3.5 permits IPv4 and IPv6 forwarding addresses in TLV 1156.
				attr := buildBGPLSAttrWithOpaque(1156, tt.value)
				update.PathAttributes = []bgp.PathAttribute{
					{AttributeType: 29, AttributeLength: uint16(len(attr)), Attribute: attr},
				}
			}
			msg, err := (&producer{}).lsPrefix(prfx, "", 0, newPeerHeader(), update, tt.proto == base.OSPFv2)
			if err != nil {
				t.Fatalf("lsPrefix() error = %v", err)
			}
			wire, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("marshal prefix: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(wire, &fields); err != nil {
				t.Fatalf("unmarshal prefix JSON: %v", err)
			}
			got, present := fields["ospf_fwd_addr"]
			if tt.want == "" {
				if present {
					t.Errorf("ospf_fwd_addr = %s, want absent", got)
				}
				return
			}
			if string(got) != strconv.Quote(tt.want) {
				t.Errorf("ospf_fwd_addr = %s, want %q", got, tt.want)
			}
		})
	}
}
