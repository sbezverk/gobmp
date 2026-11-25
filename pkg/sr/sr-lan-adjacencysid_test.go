package sr

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalLANAdjacencySIDTLV(t *testing.T) {
	tests := []struct {
		name    string
		proto   base.ProtoID
		wire    []byte
		want    *LANAdjacencySIDTLV
		errPart string
	}{
		{
			name:  "IS-IS label and reserved bits",
			proto: base.ISISL2,
			wire:  []byte{0xff, 7, 0x55, 0x66, 0, 1, 2, 3, 4, 5, 0xf1, 0x23, 0x45},
			want: &LANAdjacencySIDTLV{
				Flags:  &AdjISISFlags{FFlag: true, BFlag: true, VFlag: true, LFlag: true, SFlag: true, PFlag: true},
				Weight: 7, SID: 0x12345, NeighborID: "0001.0203.0405",
			},
		},
		{
			name:  "OSPFv2 index with high bit",
			proto: base.OSPFv2,
			wire:  []byte{0x90, 5, 0, 0, 192, 0, 2, 1, 0x80, 0, 0, 1},
			want: &LANAdjacencySIDTLV{
				Flags:  &AdjOSPFFlags{BFlag: true, GFlag: true},
				Weight: 5, SID: 0x80000001, NeighborID: "192.0.2.1",
			},
		},
		{
			name: "unsupported protocol", proto: base.Direct,
			errPart: "does not support Protocol-ID",
		},
		{
			name: "short neighbor", proto: base.ISISL1,
			wire: []byte{0, 0, 0, 0, 1, 2, 3, 4, 5}, errPart: "need 10 bytes, have 9",
		},
		{
			name: "local index flags", proto: base.OSPFv3,
			wire: []byte{0x20, 0, 0, 0, 192, 0, 2, 1, 0, 0, 0, 1}, errPart: "inconsistent V and L",
		},
		{
			name: "index width for label", proto: base.OSPFv3,
			wire: []byte{0x60, 0, 0, 0, 192, 0, 2, 1, 0, 0, 0, 1}, errPart: "need 3 bytes, have 4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLANAdjacencySIDTLV(tt.wire, tt.proto)
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
			var decoded LANAdjacencySIDTLV
			if err := json.Unmarshal(wire, &decoded); err != nil || !reflect.DeepEqual(&decoded, tt.want) {
				t.Fatalf("round trip got %+v, %v, want %+v", decoded, err, tt.want)
			}
		})
	}
}

func TestLANAdjacencySIDUnmarshalJSON(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    LANAdjacencySIDTLV
		wantErr bool
	}{
		{name: "absent flags", input: `{"sid":0,"neighbor_id":"192.0.2.1"}`, want: LANAdjacencySIDTLV{NeighborID: "192.0.2.1"}},
		{name: "null flags", input: `{"flags":null}`},
		{name: "opaque flags", input: `{"flags":{"flags":255}}`, want: LANAdjacencySIDTLV{Flags: &UnknownProtoFlags{Flags: 255}}},
		{name: "flags require object", input: `{"flags":255}`, wantErr: true},
		{name: "flag bit requires boolean", input: `{"flags":{"f_flag":1}}`, wantErr: true},
		{name: "SID overflow", input: `{"sid":4294967296}`, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var got LANAdjacencySIDTLV
			err := json.Unmarshal([]byte(tt.input), &got)
			if (err != nil) != tt.wantErr || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, %v, want %+v with error=%t", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestPointToPointAdjacencySIDUnknownProtocol(t *testing.T) {
	// The point-to-point decoder also supports protocols without a known
	// flag mapping and preserves their raw flag octet in JSON.
	got, err := UnmarshalAdjacencySIDTLV([]byte{0xad, 0, 0, 0, 0, 0, 17}, base.Direct)
	if err != nil {
		t.Fatal(err)
	}
	want := &AdjacencySIDTLV{Flags: &UnknownProtoFlags{Flags: 0xad}, SID: 17}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AdjacencySIDTLV
	if err := json.Unmarshal(wire, &decoded); err != nil || !reflect.DeepEqual(&decoded, want) {
		t.Fatalf("round trip got %+v, %v, want %+v", decoded, err, want)
	}
}
