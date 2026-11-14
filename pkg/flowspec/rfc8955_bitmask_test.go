package flowspec

import (
	"encoding/json"
	"testing"
)

// RFC 8955 Section 4.2.1.2: TCP flags (type 9) and fragment (type 12) use the
// bitmask operator, whose low bits are NOT (0x02) and MATCH (0x01), not the
// numeric GT/EQ bits.
func TestRFC8955_BitmaskOperator(t *testing.T) {
	tests := []struct {
		name            string
		in              []byte
		not, match, and bool
		wantVal         byte
	}{
		// TCP flags: match SYN exactly (EOL, match).
		{"tcp_syn_match", []byte{9, 0x81, 0x02}, false, true, false, 0x02},
		// Fragment: not IsF (EOL, not).
		{"frag_not_isf", []byte{12, 0x82, 0x02}, true, false, false, 0x02},
		// Fragment: not-match DF (EOL, AND, not, match).
		{"frag_not_match_df", []byte{12, 0xC3, 0x01}, true, true, true, 0x01},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, n, err := makeGenericSpec(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(tt.in) {
				t.Errorf("consumed %d, want %d", n, len(tt.in))
			}
			op := spec.(*GenericSpec).OpVal[0].Op
			if op.NotBit != tt.not || op.MatchBit != tt.match || op.ANDBit != tt.and {
				t.Errorf("not=%v match=%v and=%v, want %v %v %v", op.NotBit, op.MatchBit, op.ANDBit, tt.not, tt.match, tt.and)
			}
			if op.LTBit || op.GTBit || op.EQBit {
				t.Errorf("numeric bits set on bitmask operator: %+v", op)
			}
			if v := spec.(*GenericSpec).OpVal[0].Val[0]; v != tt.wantVal {
				t.Errorf("value 0x%02x, want 0x%02x", v, tt.wantVal)
			}
		})
	}
}

// Numeric components keep LT/GT/EQ decoding.
func TestRFC8955_NumericOperatorUnchanged(t *testing.T) {
	spec, _, err := makeGenericSpec([]byte{3, 0x81, 6}) // proto =6
	if err != nil {
		t.Fatal(err)
	}
	op := spec.(*GenericSpec).OpVal[0].Op
	if !op.EQBit || op.NotBit || op.MatchBit {
		t.Errorf("proto =6 decoded as %+v", op)
	}
}

func TestOperator_JSONRoundTrip(t *testing.T) {
	for _, orig := range []Operator{
		{EOLBit: true, ANDBit: true, Length: 2, LTBit: true, EQBit: true},
		{EOLBit: true, Length: 1, NotBit: true, MatchBit: true},
	} {
		b, err := json.Marshal(&orig)
		if err != nil {
			t.Fatal(err)
		}
		var got Operator
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got != orig {
			t.Errorf("round trip %s: got %+v, want %+v", b, got, orig)
		}
	}
}
