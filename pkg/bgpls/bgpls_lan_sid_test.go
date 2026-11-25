package bgpls

import (
	"slices"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestBGPLSLinkLANSIDAccessors(t *testing.T) {
	// The attribute carries repetitions, bounded malformed instances, a
	// LAN End.X SID for another IGP, and unrelated BGP-LS TLVs.
	attributes := []byte{
		0x04, 0x4c, 0, 13, 0x30, 5, 0, 0, 0, 1, 2, 3, 4, 5, 0, 0, 17, // 1100, label 17
		0x04, 0x53, 0, 28, 0, 5, 0x80, 0, 1, 0, 0, 1, 2, 3, 4, 5, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17,
		0x04, 0x4c, 0, 1, 0,
		0x04, 0x53, 0, 1, 0,
		0x04, 0x54, 0, 26, 0, 5, 0x80, 0, 1, 0, 192, 0, 2, 1, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x18,
		0x04, 0x4c, 0, 14, 0, 2, 0, 0, 0, 1, 2, 3, 4, 6, 0, 0, 0, 9, // 1100, index 9
		0x04, 0x53, 0, 28, 0, 5, 0x80, 0, 1, 0, 0, 1, 2, 3, 4, 6, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16,
		0x04, 0x44, 0, 4, 0, 0, 0, 23, // 1092, TE metric
	}
	ls, err := UnmarshalBGPLSNLRI(attributes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name     string
		proto    base.ProtoID
		wantAdj  []uint32
		wantEndX []string
	}{
		{name: "IS-IS", proto: base.ISISL1, wantAdj: []uint32{17, 9}, wantEndX: []string{"2001:db8::17", "2001:db8::16"}},
		{name: "OSPFv3", proto: base.OSPFv3, wantEndX: []string{"2001:db8::18"}},
		{name: "unsupported IGP", proto: base.Direct},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var adj []uint32
			for _, got := range ls.GetSRLANAdjacencySID(tt.proto) {
				adj = append(adj, got.SID)
			}
			var endX []string
			for _, got := range ls.GetLANSRv6EndXSID(tt.proto) {
				endX = append(endX, got.SID)
			}
			if !slices.Equal(adj, tt.wantAdj) || !slices.Equal(endX, tt.wantEndX) {
				t.Fatalf("got Adj SID %v and End.X %v, want %v and %v", adj, endX, tt.wantAdj, tt.wantEndX)
			}
			if metric := ls.GetTEDefaultMetric(); metric != 23 {
				t.Errorf("got TE metric %d, want 23", metric)
			}
		})
	}
}
