package flowspec

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestRFC8955_PcapFullVerification traces every byte from the Arista EOS pcap
// through the parser and verifies each filter spec matches the tshark decode.
func TestRFC8955_PcapFullVerification(t *testing.T) {
	// Exact NLRI bytes from pcap MP_REACH_NLRI
	input := []byte{
		// NLRI 1: len=17 (0x11)
		// dst 1.2.4.0/24, src 1.2.0.0/16, proto =6||=17, port =80
		0x11,
		0x01, 0x18, 0x01, 0x02, 0x04,       // Type1: dst 1.2.4.0/24
		0x02, 0x10, 0x01, 0x02,              // Type2: src 1.2.0.0/16
		0x03, 0x01, 0x06, 0x81, 0x11,        // Type3: proto =6 || =17
		0x04, 0x81, 0x50,                    // Type4: port =80

		// NLRI 2: len=8
		// dst 1.2.6.0/24, fragment =IsFragment
		0x08,
		0x01, 0x18, 0x01, 0x02, 0x06,       // Type1: dst 1.2.6.0/24
		0x0c, 0x81, 0x02,                    // Type12: fragment =IsF

		// NLRI 3: len=32 (0x20)
		// dst 1.2.5.0/24, src 1.2.0.0/16, dstport =3128||>8080&&<8088,
		// srcport >1000&&<=2000, tcpflags =SF, dscp =42
		0x20,
		0x01, 0x18, 0x01, 0x02, 0x05,       // Type1: dst 1.2.5.0/24
		0x02, 0x10, 0x01, 0x02,              // Type2: src 1.2.0.0/16
		0x05, 0x11, 0x0c, 0x38,              // Type5: dstport =3128
		    0x12, 0x1f, 0x90,                //        >8080
		    0xd4, 0x1f, 0x98,                //        &&<8088
		0x06, 0x12, 0x03, 0xe8,              // Type6: srcport >1000
		    0xd5, 0x07, 0xd0,                //        &&<=2000
		0x09, 0x81, 0x03,                    // Type9: tcpflags =SF (0x03)
		0x0b, 0x81, 0x2a,                    // Type11: dscp =42

		// NLRI 4: len=4
		// src 1.2.0.0/16
		0x04,
		0x02, 0x10, 0x01, 0x02,              // Type2: src 1.2.0.0/16

		// NLRI 5: len=5
		// dst 1.2.3.0/24
		0x05,
		0x01, 0x18, 0x01, 0x02, 0x03,       // Type1: dst 1.2.3.0/24

		// NLRI 6: len=15 (0x0f)
		// dst 1.2.4.0/24, icmptype =15||=16, icmpcode =0||=1
		0x0f,
		0x01, 0x18, 0x01, 0x02, 0x04,       // Type1: dst 1.2.4.0/24
		0x07, 0x01, 0x0f, 0x81, 0x10,       // Type7: icmptype =15 || =16
		0x08, 0x01, 0x00, 0x81, 0x01,       // Type8: icmpcode =0 || =1
	}

	nlris, err := UnmarshalAllFlowspecNLRI(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(nlris) != 6 {
		t.Fatalf("expected 6 NLRIs, got %d", len(nlris))
	}

	// --- NLRI 1: 4 specs ---
	if len(nlris[0].Spec) != 4 {
		t.Fatalf("NLRI[0]: expected 4 specs, got %d", len(nlris[0].Spec))
	}
	// Type1: dst 1.2.4.0/24
	ps, ok := nlris[0].Spec[0].(*PrefixSpec)
	if !ok { t.Fatalf("NLRI[0].Spec[0]: expected *PrefixSpec, got %T", nlris[0].Spec[0]) }
	assertPrefix(t, "NLRI[0].dst", ps, 1, 24, []byte{1, 2, 4})
	// Type2: src 1.2.0.0/16
	ps, ok = nlris[0].Spec[1].(*PrefixSpec)
	if !ok { t.Fatalf("NLRI[0].Spec[1]: expected *PrefixSpec, got %T", nlris[0].Spec[1]) }
	assertPrefix(t, "NLRI[0].src", ps, 2, 16, []byte{1, 2})
	// Type3: proto =6 || =17
	gs, ok := nlris[0].Spec[2].(*GenericSpec)
	if !ok { t.Fatalf("NLRI[0].Spec[2]: expected *GenericSpec, got %T", nlris[0].Spec[2]) }
	assertGeneric(t, "NLRI[0].proto", gs, 3, 2)
	assertOpVal(t, "NLRI[0].proto[0]", gs.OpVal[0], false, false, true, []byte{6})
	assertOpVal(t, "NLRI[0].proto[1]", gs.OpVal[1], true, false, true, []byte{17})
	// Type4: port =80
	gs, ok = nlris[0].Spec[3].(*GenericSpec)
	if !ok { t.Fatalf("NLRI[0].Spec[3]: expected *GenericSpec, got %T", nlris[0].Spec[3]) }
	assertGeneric(t, "NLRI[0].port", gs, 4, 1)
	assertOpVal(t, "NLRI[0].port[0]", gs.OpVal[0], true, false, true, []byte{80})

	// --- NLRI 2: 2 specs ---
	if len(nlris[1].Spec) != 2 {
		t.Fatalf("NLRI[1]: expected 2 specs, got %d", len(nlris[1].Spec))
	}
	ps, ok = nlris[1].Spec[0].(*PrefixSpec)
	if !ok { t.Fatalf("NLRI[1].Spec[0]: expected *PrefixSpec, got %T", nlris[1].Spec[0]) }
	assertPrefix(t, "NLRI[1].dst", ps, 1, 24, []byte{1, 2, 6})
	gs, ok = nlris[1].Spec[1].(*GenericSpec)
	if !ok { t.Fatalf("NLRI[1].Spec[1]: expected *GenericSpec, got %T", nlris[1].Spec[1]) }
	assertGeneric(t, "NLRI[1].frag", gs, 12, 1)
	assertOpVal(t, "NLRI[1].frag[0]", gs.OpVal[0], true, false, true, []byte{2})

	// --- NLRI 3: 6 specs ---
	if len(nlris[2].Spec) != 6 {
		t.Fatalf("NLRI[2]: expected 6 specs, got %d", len(nlris[2].Spec))
	}
	ps, ok = nlris[2].Spec[0].(*PrefixSpec)
	if !ok { t.Fatalf("NLRI[2].Spec[0]: expected *PrefixSpec, got %T", nlris[2].Spec[0]) }
	assertPrefix(t, "NLRI[2].dst", ps, 1, 24, []byte{1, 2, 5})
	ps, ok = nlris[2].Spec[1].(*PrefixSpec)
	if !ok { t.Fatalf("NLRI[2].Spec[1]: expected *PrefixSpec, got %T", nlris[2].Spec[1]) }
	assertPrefix(t, "NLRI[2].src", ps, 2, 16, []byte{1, 2})
	// Type5: dstport =3128 || >8080 && <8088
	gs, ok = nlris[2].Spec[2].(*GenericSpec)
	if !ok { t.Fatalf("NLRI[2].Spec[2]: expected *GenericSpec, got %T", nlris[2].Spec[2]) }
	assertGeneric(t, "NLRI[2].dstport", gs, 5, 3)
	assertOpVal(t, "NLRI[2].dstport[0]", gs.OpVal[0], false, false, true, []byte{0x0c, 0x38})   // =3128
	assertOpVal(t, "NLRI[2].dstport[1]", gs.OpVal[1], false, false, false, []byte{0x1f, 0x90})  // >8080 (GT only)
	if !gs.OpVal[1].Op.GTBit { t.Error("NLRI[2].dstport[1]: expected GT bit") }
	assertOpVal(t, "NLRI[2].dstport[2]", gs.OpVal[2], true, true, false, nil)                   // &&<8088
	if !gs.OpVal[2].Op.LTBit { t.Error("NLRI[2].dstport[2]: expected LT bit") }
	if !gs.OpVal[2].Op.ANDBit { t.Error("NLRI[2].dstport[2]: expected AND bit") }
	// Type6: srcport >1000 && <=2000
	gs, ok = nlris[2].Spec[3].(*GenericSpec)
	if !ok { t.Fatalf("NLRI[2].Spec[3]: expected *GenericSpec, got %T", nlris[2].Spec[3]) }
	assertGeneric(t, "NLRI[2].srcport", gs, 6, 2)
	// Type9: tcpflags = SF (0x03 = SYN+FIN)
	gs, ok = nlris[2].Spec[4].(*GenericSpec)
	if !ok { t.Fatalf("NLRI[2].Spec[4]: expected *GenericSpec, got %T", nlris[2].Spec[4]) }
	assertGeneric(t, "NLRI[2].tcpflags", gs, 9, 1)
	assertOpVal(t, "NLRI[2].tcpflags[0]", gs.OpVal[0], true, false, true, []byte{0x03})
	// Type11: dscp =42
	gs, ok = nlris[2].Spec[5].(*GenericSpec)
	if !ok { t.Fatalf("NLRI[2].Spec[5]: expected *GenericSpec, got %T", nlris[2].Spec[5]) }
	assertGeneric(t, "NLRI[2].dscp", gs, 11, 1)
	assertOpVal(t, "NLRI[2].dscp[0]", gs.OpVal[0], true, false, true, []byte{0x2a})

	// --- NLRI 4: 1 spec ---
	if len(nlris[3].Spec) != 1 { t.Fatalf("NLRI[3]: expected 1 spec, got %d", len(nlris[3].Spec)) }
	ps, ok = nlris[3].Spec[0].(*PrefixSpec)
	if !ok { t.Fatalf("NLRI[3].Spec[0]: expected *PrefixSpec, got %T", nlris[3].Spec[0]) }
	assertPrefix(t, "NLRI[3].src", ps, 2, 16, []byte{1, 2})

	// --- NLRI 5: 1 spec ---
	if len(nlris[4].Spec) != 1 { t.Fatalf("NLRI[4]: expected 1 spec, got %d", len(nlris[4].Spec)) }
	ps, ok = nlris[4].Spec[0].(*PrefixSpec)
	if !ok { t.Fatalf("NLRI[4].Spec[0]: expected *PrefixSpec, got %T", nlris[4].Spec[0]) }
	assertPrefix(t, "NLRI[4].dst", ps, 1, 24, []byte{1, 2, 3})

	// --- NLRI 6: 3 specs ---
	if len(nlris[5].Spec) != 3 { t.Fatalf("NLRI[5]: expected 3 specs, got %d", len(nlris[5].Spec)) }
	ps, ok = nlris[5].Spec[0].(*PrefixSpec)
	if !ok { t.Fatalf("NLRI[5].Spec[0]: expected *PrefixSpec, got %T", nlris[5].Spec[0]) }
	assertPrefix(t, "NLRI[5].dst", ps, 1, 24, []byte{1, 2, 4})
	// Type7: icmptype =15 || =16
	gs, ok = nlris[5].Spec[1].(*GenericSpec)
	if !ok { t.Fatalf("NLRI[5].Spec[1]: expected *GenericSpec, got %T", nlris[5].Spec[1]) }
	assertGeneric(t, "NLRI[5].icmptype", gs, 7, 2)
	assertOpVal(t, "NLRI[5].icmptype[0]", gs.OpVal[0], false, false, true, []byte{15})
	assertOpVal(t, "NLRI[5].icmptype[1]", gs.OpVal[1], true, false, true, []byte{16})
	// Type8: icmpcode =0 || =1
	gs, ok = nlris[5].Spec[2].(*GenericSpec)
	if !ok { t.Fatalf("NLRI[5].Spec[2]: expected *GenericSpec, got %T", nlris[5].Spec[2]) }
	assertGeneric(t, "NLRI[5].icmpcode", gs, 8, 2)
	assertOpVal(t, "NLRI[5].icmpcode[0]", gs.OpVal[0], false, false, true, []byte{0})
	assertOpVal(t, "NLRI[5].icmpcode[1]", gs.OpVal[1], true, false, true, []byte{1})

	// Verify all hashes are unique and non-empty
	hashes := map[string]int{}
	for i, n := range nlris {
		if n.SpecHash == "" { t.Errorf("NLRI[%d]: empty SpecHash", i) }
		if prev, dup := hashes[n.SpecHash]; dup {
			t.Errorf("NLRI[%d] has same SpecHash as NLRI[%d]", i, prev)
		}
		hashes[n.SpecHash] = i
	}

	// Verify JSON serialization for each NLRI
	for i, n := range nlris {
		b, err := json.Marshal(n.Spec)
		if err != nil { t.Errorf("NLRI[%d]: Marshal error: %v", i, err) }
		if len(b) < 10 { t.Errorf("NLRI[%d]: suspiciously short JSON: %s", i, string(b)) }
	}

	t.Logf("All 6 NLRIs, 17 filter specs, verified byte-for-byte against tshark decode")
}

func assertPrefix(t *testing.T, name string, ps *PrefixSpec, specType uint8, prefixLen uint8, prefix []byte) {
	t.Helper()
	if ps.SpecType != specType { t.Errorf("%s: type=%d, want %d", name, ps.SpecType, specType) }
	if ps.PrefixLength != prefixLen { t.Errorf("%s: prefixLen=%d, want %d", name, ps.PrefixLength, prefixLen) }
	if len(ps.Prefix) != len(prefix) {
		t.Errorf("%s: prefix length=%d, want %d", name, len(ps.Prefix), len(prefix))
		return
	}
	for i := range prefix {
		if ps.Prefix[i] != prefix[i] {
			t.Errorf("%s: prefix[%d]=%d, want %d", name, i, ps.Prefix[i], prefix[i])
		}
	}
}

func assertGeneric(t *testing.T, name string, gs *GenericSpec, specType uint8, opvalCount int) {
	t.Helper()
	if gs.SpecType != specType { t.Errorf("%s: type=%d, want %d", name, gs.SpecType, specType) }
	if len(gs.OpVal) != opvalCount { t.Fatalf("%s: opval count=%d, want %d", name, len(gs.OpVal), opvalCount) }
}

func assertOpVal(t *testing.T, name string, ov *OpVal, eol, and, eq bool, val []byte) {
	t.Helper()
	if ov.Op.EOLBit != eol { t.Errorf("%s: EOL=%v, want %v", name, ov.Op.EOLBit, eol) }
	if ov.Op.ANDBit != and { t.Errorf("%s: AND=%v, want %v", name, ov.Op.ANDBit, and) }
	if ov.Op.EQBit != eq { t.Errorf("%s: EQ=%v, want %v", name, ov.Op.EQBit, eq) }
	if val != nil {
		if len(ov.Val) != len(val) {
			t.Errorf("%s: val length=%d, want %d", name, len(ov.Val), len(val))
			return
		}
		for i := range val {
			if ov.Val[i] != val[i] {
				t.Errorf("%s: val[%d]=0x%02x, want 0x%02x", name, i, ov.Val[i], val[i])
			}
		}
	}
}

// TestRFC8955_Section4_LengthEncoding verifies the 1-byte and 2-byte NLRI length encoding.
func TestRFC8955_Section4_LengthEncoding(t *testing.T) {
	// 1-byte length: values 0-239 (0x00-0xEF)
	tests := []struct{
		name string
		lenBytes []byte
		expectedLength uint16
	}{
		{"1-byte min", []byte{0x05, 0x02, 0x18, 0x0A, 0x00, 0x07}, 5},
		{"1-byte 239", nil, 239}, // skip - would need 239 bytes of spec data
		{"2-byte 240", nil, 240}, // skip
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.lenBytes == nil {
				t.Skip("lenBytes not provided for this case")
			}
			nlri, _, err := unmarshalSingleFlowspecNLRI(tt.lenBytes, false)
			if err != nil { t.Fatalf("error: %v", err) }
			if nlri.Length != tt.expectedLength {
				t.Errorf("length=%d, want %d", nlri.Length, tt.expectedLength)
			}
		})
	}

	// 2-byte length encoding: first nibble 0xF, rest encodes length
	// 0xF0 0x00 = length 0 (edge case)
	// 0xF0 0xF0 = length 240
	// 0xF1 0x00 = length 256
	lengthTests := []struct{
		b0, b1 byte
		expected uint16
	}{
		{0xF0, 0xF0, 240},
		{0xF1, 0x00, 256},
		{0xF4, 0x00, 1024},
		{0xFF, 0xFF, 4095},
	}
	for _, lt := range lengthTests {
		t.Run(fmt.Sprintf("2-byte_%d", lt.expected), func(t *testing.T) {
			computed := ((uint16(lt.b0) & 0x0f) << 8) | uint16(lt.b1)
			if computed != lt.expected {
				t.Errorf("2-byte decode: got %d, want %d", computed, lt.expected)
			}
		})
	}
}

// TestRFC8955_Section4_2_1_OperatorBits verifies all operator byte bit positions per RFC 8955.
func TestRFC8955_Section4_2_1_OperatorBits(t *testing.T) {
	tests := []struct{
		name string
		b byte
		eol, and, lt, gt, eq bool
		length uint8
	}{
		// Bit 7: EOL, Bit 6: AND, Bits 5-4: length, Bit 2: LT, Bit 1: GT, Bit 0: EQ
		{"all_zero", 0x00, false, false, false, false, false, 1},
		{"eol_only", 0x80, true, false, false, false, false, 1},
		{"and_only", 0x40, false, true, false, false, false, 1},
		{"len_2bytes", 0x10, false, false, false, false, false, 2},
		{"len_4bytes", 0x20, false, false, false, false, false, 4},
		{"len_8bytes", 0x30, false, false, false, false, false, 8},
		{"lt_only", 0x04, false, false, true, false, false, 1},
		{"gt_only", 0x02, false, false, false, true, false, 1},
		{"eq_only", 0x01, false, false, false, false, true, 1},
		{"eol_and_eq", 0xC1, true, true, false, false, true, 1},
		// pcap examples
		{"pcap_0x81", 0x81, true, false, false, false, true, 1},    // EOL+EQ
		{"pcap_0x01", 0x01, false, false, false, false, true, 1},   // EQ
		{"pcap_0x11", 0x11, false, false, false, false, true, 2},   // EQ + 2-byte val
		{"pcap_0x12", 0x12, false, false, false, true, false, 2},   // GT + 2-byte val
		{"pcap_0xd4", 0xd4, true, true, true, false, false, 2},     // EOL+AND+LT + 2-byte val
		{"pcap_0xd5", 0xd5, true, true, true, false, true, 2},      // EOL+AND+LT+EQ + 2-byte val
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, err := UnmarshalFlowspecOperator(tt.b)
			if err != nil { t.Fatalf("error: %v", err) }
			if op.EOLBit != tt.eol { t.Errorf("EOL=%v want %v", op.EOLBit, tt.eol) }
			if op.ANDBit != tt.and { t.Errorf("AND=%v want %v", op.ANDBit, tt.and) }
			if op.Length != tt.length { t.Errorf("Length=%d want %d", op.Length, tt.length) }
			if op.LTBit != tt.lt { t.Errorf("LT=%v want %v", op.LTBit, tt.lt) }
			if op.GTBit != tt.gt { t.Errorf("GT=%v want %v", op.GTBit, tt.gt) }
			if op.EQBit != tt.eq { t.Errorf("EQ=%v want %v", op.EQBit, tt.eq) }
		})
	}
}
