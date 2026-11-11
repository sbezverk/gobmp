package ls

import (
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/gobmp/pkg/te"
)

// rdType0 builds an 8-byte RD of type 0: 2-byte type + 2-byte AS + 4-byte assigned number.
func rdType0(as uint16, assigned uint32) []byte {
	return []byte{
		0x00, 0x00, // type 0
		byte(as >> 8), byte(as),
		byte(assigned >> 24), byte(assigned >> 16), byte(assigned >> 8), byte(assigned),
	}
}

func TestUnmarshalLSNLRI72(t *testing.T) {
	// One Node NLRI (type 1) body reused from ls-nlri71_test.go.
	// 0x1A is the Local Node Descriptor TLV length, not the element body length.
	nodeBody := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x1A,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	// RFC 9552 §5.2 Figure 6: Type + Length (including RD) + RD + body.
	makeEntry := func(rd []byte, elType uint16, body []byte) []byte {
		out := make([]byte, 0, len(rd)+4+len(body))
		out = append(out, byte(elType>>8), byte(elType))
		length := len(rd) + len(body)
		out = append(out, byte(length>>8), byte(length))
		out = append(out, rd...)
		out = append(out, body...)
		return out
	}

	t.Run("single node element with RD type 0", func(t *testing.T) {
		rd := rdType0(100, 1)
		input := makeEntry(rd, 1, nodeBody)
		got, err := UnmarshalLSNLRI72(input, false)
		if err != nil {
			t.Fatalf("UnmarshalLSNLRI72 error: %v", err)
		}
		if len(got.NLRI) != 1 {
			t.Fatalf("len(NLRI) = %d, want 1", len(got.NLRI))
		}
		el := got.NLRI[0]
		if el.RD == nil {
			t.Fatal("RD is nil, want populated")
		}
		if el.RD.Type != 0 {
			t.Errorf("RD.Type = %d, want 0", el.RD.Type)
		}
		if got := el.RD.String(); got != "100:1" {
			t.Errorf("RD.String() = %q, want \"100:1\"", got)
		}
		if el.Type != 1 {
			t.Errorf("Element.Type = %d, want 1", el.Type)
		}
		if el.Length != uint16(8+len(nodeBody)) {
			t.Errorf("Element.Length = %d, want %d including RD", el.Length, 8+len(nodeBody))
		}
		if _, ok := el.LS.(*base.NodeNLRI); !ok {
			t.Errorf("Element.LS type = %T, want *base.NodeNLRI", el.LS)
		}
		if el.PathID != 0 {
			t.Errorf("PathID = %d, want 0 (pathID=false)", el.PathID)
		}
	})

	t.Run("multiple elements preserve RD per-element", func(t *testing.T) {
		input := makeEntry(rdType0(100, 1), 1, nodeBody)
		input = append(input, makeEntry(rdType0(200, 2), 1, nodeBody)...)
		got, err := UnmarshalLSNLRI72(input, false)
		if err != nil {
			t.Fatalf("UnmarshalLSNLRI72 error: %v", err)
		}
		if len(got.NLRI) != 2 {
			t.Fatalf("len(NLRI) = %d, want 2", len(got.NLRI))
		}
		if got.NLRI[0].RD.String() != "100:1" {
			t.Errorf("NLRI[0].RD = %q, want \"100:1\"", got.NLRI[0].RD.String())
		}
		if got.NLRI[1].RD.String() != "200:2" {
			t.Errorf("NLRI[1].RD = %q, want \"200:2\"", got.NLRI[1].RD.String())
		}
	})

	t.Run("link element decoded", func(t *testing.T) {
		// Link body reused from ls-nlri71_test.go (type 2 element body, no Type/Length header).
		linkBody := []byte{
			0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x1A,
			0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
			0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
			0x01, 0x01, 0x00, 0x1A,
			0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
			0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
			0x01, 0x05, 0x00, 0x10,
			0xFC, 0x00, 0xDD, 0xDD, 0x00, 0x03, 0x00, 0x05,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
			0x01, 0x06, 0x00, 0x10,
			0xFC, 0x00, 0xDD, 0xDD, 0x00, 0x03, 0x00, 0x05,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
			0x01, 0x07, 0x00, 0x02, 0x00, 0x02,
		}
		input := makeEntry(rdType0(100, 1), 2, linkBody)
		got, err := UnmarshalLSNLRI72(input, false)
		if err != nil {
			t.Fatalf("UnmarshalLSNLRI72 error: %v", err)
		}
		if len(got.NLRI) != 1 || got.NLRI[0].Type != 2 {
			t.Fatalf("got %d elements / type %d, want 1 / 2", len(got.NLRI), got.NLRI[0].Type)
		}
		if _, ok := got.NLRI[0].LS.(*base.LinkNLRI); !ok {
			t.Errorf("LS type = %T, want *base.LinkNLRI", got.NLRI[0].LS)
		}
	})

	t.Run("prefix v4 element decoded", func(t *testing.T) {
		// Prefix v4 body: Protocol-ID(1) + Identifier(8) + Local Node Descriptor TLV + IP Reachability TLV
		prefixV4Body := []byte{
			0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x1A,
			0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
			0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
			0x01, 0x09, 0x00, 0x05, 0x18, 0x0A, 0x00, 0x00, 0x00,
		}
		input := makeEntry(rdType0(100, 1), 3, prefixV4Body)
		got, err := UnmarshalLSNLRI72(input, false)
		if err != nil {
			t.Fatalf("UnmarshalLSNLRI72 error: %v", err)
		}
		if len(got.NLRI) != 1 || got.NLRI[0].Type != 3 {
			t.Fatalf("got %d elements / type %d, want 1 / 3", len(got.NLRI), got.NLRI[0].Type)
		}
		if _, ok := got.NLRI[0].LS.(*base.PrefixNLRI); !ok {
			t.Errorf("LS type = %T, want *base.PrefixNLRI", got.NLRI[0].LS)
		}
	})

	t.Run("prefix v6 element decoded", func(t *testing.T) {
		// IPv6 Prefix Descriptor: IP Reachability TLV with /128 IPv6 prefix.
		prefixV6Body := []byte{
			0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x1A,
			0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
			0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
			// IP Reachability TLV (type 265, length 17): /128 then 16 bytes of 2001:db8::1
			0x01, 0x09, 0x00, 0x11, 0x80,
			0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		}
		input := makeEntry(rdType0(100, 1), 4, prefixV6Body)
		got, err := UnmarshalLSNLRI72(input, false)
		if err != nil {
			t.Fatalf("UnmarshalLSNLRI72 error: %v", err)
		}
		if len(got.NLRI) != 1 || got.NLRI[0].Type != 4 {
			t.Fatalf("got %d elements / type %d, want 1 / 4", len(got.NLRI), got.NLRI[0].Type)
		}
		if _, ok := got.NLRI[0].LS.(*base.PrefixNLRI); !ok {
			t.Errorf("LS type = %T, want *base.PrefixNLRI", got.NLRI[0].LS)
		}
	})

	t.Run("TE policy element decoded", func(t *testing.T) {
		// TE Policy NLRI: ProtocolID(1) + Identifier(8) + Node Descriptor TLV with type 256.
		teBody := []byte{
			0x09,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x10,
			0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
			0x02, 0x04, 0x00, 0x04, 0xC0, 0xA8, 0x01, 0x01,
		}
		input := makeEntry(rdType0(100, 1), 5, teBody)
		got, err := UnmarshalLSNLRI72(input, false)
		if err != nil {
			t.Fatalf("UnmarshalLSNLRI72 error: %v", err)
		}
		if len(got.NLRI) != 1 || got.NLRI[0].Type != 5 {
			t.Fatalf("got %d elements / type %d, want 1 / 5", len(got.NLRI), got.NLRI[0].Type)
		}
		if _, ok := got.NLRI[0].LS.(*te.NLRI); !ok {
			t.Errorf("LS type = %T, want *te.NLRI", got.NLRI[0].LS)
		}
	})

	t.Run("SRv6 SID element decoded", func(t *testing.T) {
		sidBody := []byte{
			0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x1A,
			0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xCE,
			0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93,
			0x01, 0x07, 0x00, 0x02, 0x00, 0x02,
			0x02, 0x06, 0x00, 0x10,
			0x01, 0x92, 0x01, 0x68, 0x00, 0x93, 0x00, 0x00,
			0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		input := makeEntry(rdType0(100, 1), 6, sidBody)
		got, err := UnmarshalLSNLRI72(input, false)
		if err != nil {
			t.Fatalf("UnmarshalLSNLRI72 error: %v", err)
		}
		if len(got.NLRI) != 1 || got.NLRI[0].Type != 6 {
			t.Fatalf("got %d elements / type %d, want 1 / 6", len(got.NLRI), got.NLRI[0].Type)
		}
		if _, ok := got.NLRI[0].LS.(*srv6.SIDNLRI); !ok {
			t.Errorf("LS type = %T, want *srv6.SIDNLRI", got.NLRI[0].LS)
		}
	})

	t.Run("truncated Path-ID rejected", func(t *testing.T) {
		_, err := UnmarshalLSNLRI72([]byte{0xDE, 0xAD, 0xBE}, true)
		if err == nil || !strings.Contains(err.Error(), "Path-ID") {
			t.Fatalf("expected Path-ID truncation error, got %v", err)
		}
	})

	t.Run("Add Path Path-ID consumed before Type and Length", func(t *testing.T) {
		entry := makeEntry(rdType0(100, 1), 1, nodeBody)
		// Prepend 4-byte Path-ID = 0xDEADBEEF.
		input := append([]byte{0xDE, 0xAD, 0xBE, 0xEF}, entry...)
		got, err := UnmarshalLSNLRI72(input, true)
		if err != nil {
			t.Fatalf("UnmarshalLSNLRI72 error: %v", err)
		}
		if len(got.NLRI) != 1 {
			t.Fatalf("len(NLRI) = %d, want 1", len(got.NLRI))
		}
		if got.NLRI[0].PathID != 0xDEADBEEF {
			t.Errorf("PathID = %#x, want 0xDEADBEEF", got.NLRI[0].PathID)
		}
		if got.NLRI[0].RD.String() != "100:1" {
			t.Errorf("RD = %q, want \"100:1\"", got.NLRI[0].RD.String())
		}
	})

	t.Run("empty input rejected", func(t *testing.T) {
		_, err := UnmarshalLSNLRI72(nil, false)
		if err == nil {
			t.Fatal("expected error on empty input")
		}
	})

	t.Run("truncated RD rejected", func(t *testing.T) {
		_, err := UnmarshalLSNLRI72([]byte{0x00, 0x63, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00}, false)
		if err == nil || !strings.Contains(err.Error(), "need 8 bytes, have 7") {
			t.Fatalf("expected NLRI value truncation error, got %v", err)
		}
	})

	t.Run("invalid RD type rejected", func(t *testing.T) {
		// RD type 3 is invalid per RFC 4364 §4.2; base.MakeRD rejects it.
		badRD := []byte{0x00, 0x03, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01}
		input := makeEntry(badRD, 1, nodeBody)
		_, err := UnmarshalLSNLRI72(input, false)
		if err == nil || !strings.Contains(err.Error(), "Route Distinguisher") {
			t.Fatalf("expected invalid Route Distinguisher error, got %v", err)
		}
	})

	t.Run("truncated TLV header before RD rejected", func(t *testing.T) {
		_, err := UnmarshalLSNLRI72([]byte{0x00, 0x01, 0x00}, false)
		if err == nil || !strings.Contains(err.Error(), "TLV header") {
			t.Fatalf("expected TLV header truncation error, got %v", err)
		}
	})

	t.Run("empty Node body rejected", func(t *testing.T) {
		input := makeEntry(rdType0(100, 1), 1, nil)
		_, err := UnmarshalLSNLRI72(input, false)
		if err == nil {
			t.Fatal("expected error for empty Node body")
		}
	})

	// RFC 9552 §5.2: unknown types are opaque; an empty body still has an RD.
	t.Run("empty unknown body kept", func(t *testing.T) {
		input := makeEntry(rdType0(100, 1), 100, nil)
		input = append(input, makeEntry(rdType0(100, 1), 99, []byte{0xff})...)
		got, err := UnmarshalLSNLRI72(input, false)
		if err != nil {
			t.Fatalf("UnmarshalLSNLRI72() error = %v", err)
		}
		if len(got.NLRI) != 2 || got.NLRI[0].Type != 100 || got.NLRI[1].Type != 99 {
			t.Fatalf("UnmarshalLSNLRI72() elements = %+v, want types 100 and 99", got.NLRI)
		}
		if b, ok := got.NLRI[0].LS.([]byte); !ok || len(b) != 0 {
			t.Errorf("element 0 LS = %#v, want empty []byte", got.NLRI[0].LS)
		}
	})

	t.Run("truncated TLV value rejected", func(t *testing.T) {
		input := makeEntry(rdType0(100, 1), 1, nodeBody)
		input = input[:len(input)-1]
		_, err := UnmarshalLSNLRI72(input, false)
		if err == nil || !strings.Contains(err.Error(), "truncated") {
			t.Fatalf("expected truncation error, got %v", err)
		}
	})

	t.Run("unknown TLV type preserved as raw bytes", func(t *testing.T) {
		// Type 99 not in switch; should fall through to default and copy bytes.
		payload := []byte{0xAB, 0xCD, 0xEF}
		input := makeEntry(rdType0(100, 1), 99, payload)
		got, err := UnmarshalLSNLRI72(input, false)
		if err != nil {
			t.Fatalf("UnmarshalLSNLRI72 error: %v", err)
		}
		raw, ok := got.NLRI[0].LS.([]byte)
		if !ok {
			t.Fatalf("LS type = %T, want []byte", got.NLRI[0].LS)
		}
		if string(raw) != string(payload) {
			t.Errorf("raw = %x, want %x", raw, payload)
		}
	})
}
