package srv6

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalLANEndXSIDTLV(t *testing.T) {
	isis := []byte{
		0, 5, 0xe7, 128, 17, 0xff, // Behavior, flags, algorithm, weight, reserved.
		0, 1, 2, 3, 4, 5,
		0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12,
	}
	ospf := []byte{
		0, 6, 0, 0, 0, 0,
		192, 0, 2, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1,
	}
	tests := []struct {
		name    string
		proto   base.ProtoID
		typ     uint16
		wire    []byte
		want    *LANEndXSIDTLV
		errPart string
	}{
		{
			name: "IS-IS with known and opaque sub-TLVs", proto: base.ISISL2, typ: 1107,
			wire: append(bytes.Clone(isis), 0x04, 0xe4, 0, 4, 32, 16, 64, 16, 0xff, 0xff, 0, 1, 0xaa),
			want: &LANEndXSIDTLV{NeighborID: "0001.0203.0405", EndXSIDTLV: EndXSIDTLV{
				Type: 1107, Length: 41, EndpointBehavior: 5, Flags: &EndXSIDFlags{BFlag: true, SFlag: true, PFlag: true},
				Algorithm: 128, Weight: 17, SID: "2001:db8:1::12",
				SubTLVs: []SubTLV{
					&SIDStructure{Type: 1252, Length: 8, LBLength: 32, LNLength: 16, FunLength: 64, ArgLength: 16},
					&UnknownSrv6SubTLV{Type: 65535, Length: 5, Value: []byte{0xaa}},
				},
			}},
		},
		{
			name: "OSPFv3 mapped SID keeps IPv6 form", proto: base.OSPFv3, typ: 1108, wire: ospf,
			want: &LANEndXSIDTLV{NeighborID: "192.0.2.1", EndXSIDTLV: EndXSIDTLV{
				Type: 1108, Length: 26, EndpointBehavior: 6, Flags: &EndXSIDFlags{}, SID: "::ffff:192.0.2.1",
			}},
		},
		{name: "wrong protocol", proto: base.OSPFv2, typ: 1108, wire: ospf, errPart: "does not support Protocol-ID"},
		{name: "short SID", proto: base.OSPFv3, typ: 1108, wire: ospf[:25], errPart: "need at least 26 bytes, have 25"},
		{name: "length overflow", proto: base.OSPFv3, typ: 1108, wire: make([]byte, math.MaxUint16+1), errPart: "need at most 65535 bytes"},
		{name: "short sub-TLV header", proto: base.ISISL1, typ: 1107, wire: append(bytes.Clone(isis), 1, 2, 3), errPart: "header: need 4 bytes, have 3"},
		{name: "reserved sub-TLV type", proto: base.ISISL1, typ: 1107, wire: append(bytes.Clone(isis), 0, 0, 0, 0), errPart: "reserved sub-TLV type 0"},
		{name: "short sub-TLV value", proto: base.ISISL1, typ: 1107, wire: append(bytes.Clone(isis), 0x04, 0xe4, 0, 4, 32), errPart: "1252: need 4 bytes, have 1"},
		{name: "SID Structure wrong width", proto: base.ISISL1, typ: 1107, wire: append(bytes.Clone(isis), 0x04, 0xe4, 0, 3, 32, 16, 64), errPart: "Structure: need 4 bytes, have 3"},
		{name: "SID Structure over 128 bits", proto: base.ISISL1, typ: 1107, wire: append(bytes.Clone(isis), 0x04, 0xe4, 0, 4, 32, 16, 64, 17), errPart: "length sum 129"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLANEndXSIDTLV(tt.wire, tt.typ, tt.proto)
			if tt.errPart != "" {
				if got != nil || err == nil || !strings.Contains(err.Error(), tt.errPart) {
					t.Fatalf("got %+v, %v, want error containing %q", got, err, tt.errPart)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, %v, want %+v", got, err, tt.want)
			}
			wire, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var decoded LANEndXSIDTLV
			if err := json.Unmarshal(wire, &decoded); err != nil || !reflect.DeepEqual(&decoded, tt.want) {
				t.Fatalf("round trip got %+v, %v, want %+v", decoded, err, tt.want)
			}
		})
	}
}

func TestLANEndXSIDUnmarshalJSONErrors(t *testing.T) {
	for _, tt := range []struct{ name, input string }{
		{name: "neighbor ID type", input: `{"neighbor_id":192}`},
		{name: "algorithm range", input: `{"neighbor_id":"192.0.2.1","algorithm":256}`},
		{name: "nested SID Structure length missing", input: `{"neighbor_id":"192.0.2.1","sub_tlvs":[{"type":1252}]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var sid LANEndXSIDTLV
			if err := json.Unmarshal([]byte(tt.input), &sid); err == nil {
				t.Fatal("expected error decoding malformed LAN End.X SID JSON")
			}
		})
	}
}
