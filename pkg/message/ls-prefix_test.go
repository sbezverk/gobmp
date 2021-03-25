package message

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/sr"
)

func TestRoundTripLSPrefix(t *testing.T) {
	original := &LSPrefix{
		Key:        "Key",
		ID:         "ID",
		Rev:        "Rev",
		ProtocolID: base.ISISL1,
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
