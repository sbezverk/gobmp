package flowspec

import (
	"encoding/json"
	"fmt"
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

// An Operator marshalled by value bypasses MarshalJSON and is written with
// its Go field names; the reader still accepts that form.
func TestOperator_JSONReadsGoFieldNames(t *testing.T) {
	for _, orig := range []Operator{
		{EOLBit: true, ANDBit: true, Length: 2, LTBit: true, GTBit: true, EQBit: true},
		{Length: 1, NotBit: true, MatchBit: true},
	} {
		b, err := json.Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}
		got := Operator{EQBit: true, Length: 7}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got != orig {
			t.Errorf("%s: got %+v, want %+v", b, got, orig)
		}
	}
}

// TestGenericSpec_PublishesBitmaskAsGreaterThanEqual checks that TCP flags and
// fragment operators keep the published keys, greater_than for NOT and equal
// for Match, and that the JSON reads back to the same bits.
func TestGenericSpec_PublishesBitmaskAsGreaterThanEqual(t *testing.T) {
	op := &Operator{EOLBit: true, Length: 1, NotBit: true, MatchBit: true}
	for _, specType := range []uint8{9, 12} {
		g := &GenericSpec{SpecType: specType, OpVal: []*OpVal{{Op: op, Val: []byte{2}}, nil}}
		b, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf(`{"type":%d,"op_val_pairs":[{"operator":{"end_of_list_bit":true,"value_length":1,"greater_than":true,"equal":true},"value":"Ag=="},null]}`, specType)
		if string(b) != want {
			t.Errorf("type %d published %s, want %s", specType, b, want)
		}
		if !op.NotBit || !op.MatchBit || op.GTBit || op.EQBit {
			t.Fatalf("marshal changed the operator: %+v", *op)
		}
		var got GenericSpec
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if *got.OpVal[0].Op != *op {
			t.Errorf("type %d read back %+v, want %+v", specType, *got.OpVal[0].Op, *op)
		}
	}
	numeric := &GenericSpec{SpecType: 3, OpVal: []*OpVal{{Op: &Operator{Length: 1, GTBit: true}, Val: []byte{6}}}}
	if b, _ := json.Marshal(numeric); string(b) != `{"type":3,"op_val_pairs":[{"operator":{"value_length":1,"greater_than":true},"value":"Bg=="}]}` {
		t.Errorf("numeric operator published %s", b)
	}
}

// Readers map greater_than to the NOT bit and equal to the Match bit on types
// 9 and 12, and also accept the not and match keys.
func TestGenericSpec_ReadsHistoricalBitmaskKeys(t *testing.T) {
	tests := []struct {
		name string
		json string
		want Operator
	}{
		{"tcp_flags_equal", `{"type":9,"op_val_pairs":[{"operator":{"end_of_list_bit":true,"value_length":1,"equal":true},"value":"Ag=="}]}`,
			Operator{EOLBit: true, Length: 1, MatchBit: true}},
		{"fragment_greater_than_equal", `{"type":12,"op_val_pairs":[{"operator":{"and_bit":true,"greater_than":true,"equal":true},"value":"AQ=="}]}`,
			Operator{ANDBit: true, NotBit: true, MatchBit: true}},
		{"fragment_rfc_keys", `{"type":12,"op_val_pairs":[{"operator":{"not":true},"value":"AQ=="}]}`,
			Operator{NotBit: true}},
		{"tcp_flags_equal_true_match_false", `{"type":9,"op_val_pairs":[{"operator":{"equal":true,"match":false},"value":"Ag=="}]}`,
			Operator{MatchBit: true}},
		{"tcp_flags_greater_than_false_not_true", `{"type":9,"op_val_pairs":[{"operator":{"greater_than":false,"not":true},"value":"Ag=="}]}`,
			Operator{NotBit: true}},
		{"fragment_explicit_false", `{"type":12,"op_val_pairs":[{"operator":{"greater_than":false,"equal":false,"not":false,"match":false},"value":"AQ=="}]}`,
			Operator{}},
		{"protocol_numeric_unchanged", `{"type":3,"op_val_pairs":[{"operator":{"greater_than":true,"equal":true},"value":"Bg=="}]}`,
			Operator{GTBit: true, EQBit: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var g GenericSpec
			if err := json.Unmarshal([]byte(tt.json), &g); err != nil {
				t.Fatal(err)
			}
			if got := *g.OpVal[0].Op; got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
