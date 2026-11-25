package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestLSPrefixPublishesSRMSRange(t *testing.T) {
	nlri := lsPathFixtures()[2].wire
	tests := []struct {
		name      string
		value     []byte
		wantRange uint16
	}{
		{"range only", []byte{0, 0, 0, 100, 0x04, 0x86, 0, 8, 0, 128, 0, 0, 0, 0, 0, 42}, 100},
		{"truncated range", []byte{0, 0, 0}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reach := append([]byte{0x40, 4, 71, 4, 192, 0, 2, 2, 0}, nlri...)
			reach[13] = byte(base.ISISL2)
			mp, err := bgp.UnmarshalMPReachNLRI(reach, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			p.processMPUpdate(mp, AddPrefix, minimalPeerHeader(),
				testLSUpdate(lsSPFTLV{typeID: 1159, value: tt.value}))
			if len(publisher.msgs) != 1 || publisher.msgs[0].msgType != bmp.LSPrefixMsg {
				t.Fatalf("published %d records, want one BGP-LS Prefix event", len(publisher.msgs))
			}
			var got LSPrefix
			if err := json.Unmarshal(publisher.msgs[0].payload, &got); err != nil {
				t.Fatal(err)
			}
			if tt.wantRange == 0 {
				if got.PrefixAttrTLVs != nil {
					t.Fatalf("prefix attributes = %+v, want absent", got.PrefixAttrTLVs)
				}
			} else if got.PrefixAttrTLVs == nil || got.PrefixAttrTLVs.Range == nil ||
				got.PrefixAttrTLVs.Range.RangeSize != tt.wantRange {
				t.Fatalf("published %s, want SRMS range size %d", publisher.msgs[0].payload, tt.wantRange)
			}
		})
	}
}
