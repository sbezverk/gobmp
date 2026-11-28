package bgp

import (
	"encoding/json"
	"strings"
	"testing"
)

// RFC 9252 §7 treat-as-withdraw is requested only for a malformed SRv6 Service
// TLV, and only the first Prefix-SID attribute counts (RFC 7606 §3(g)).
func TestBaseAttributesSRv6ServiceMalformed(t *testing.T) {
	prefixSID := func(value ...byte) []byte { return buildAttr(0xC0, 40, value) }
	var (
		labelIndex      = prefixSID(0x01, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0xa4)
		shortLabelIndex = prefixSID(0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0)
		badL3           = prefixSID(0x05, 0x00, 0x00)
		badL2           = prefixSID(0x06, 0x00, 0x00)
		overrun         = prefixSID(0x09, 0x00, 0x04)
	)
	tests := []struct {
		name       string
		attrs      [][]byte
		want       bool
		wantLegacy bool // bgp_prefix_sid is published
		wantSID    bool // prefix_sid is published
	}{
		{name: "a malformed L3 Service TLV sets the flag", attrs: [][]byte{badL3}, want: true, wantLegacy: true},
		{name: "a malformed L2 Service TLV sets the flag", attrs: [][]byte{badL2}, want: true, wantLegacy: true},
		{name: "a bad Label-Index length leaves a decoded prefix_sid", attrs: [][]byte{shortLabelIndex},
			wantSID: true},
		{name: "an unparseable attribute publishes no prefix_sid", attrs: [][]byte{overrun}},
		{name: "a valid attribute leaves the flag unset", attrs: [][]byte{labelIndex}, wantLegacy: true, wantSID: true},
		{name: "a later malformed attribute is ignored", attrs: [][]byte{labelIndex, badL3},
			wantLegacy: true, wantSID: true},
		{name: "a later valid attribute does not replace a malformed one", attrs: [][]byte{badL3, labelIndex},
			want: true, wantLegacy: true},
		{name: "a later valid attribute does not replace a discarded one",
			attrs: [][]byte{overrun, labelIndex}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw []byte
			for _, attr := range tt.attrs {
				raw = append(raw, attr...)
			}
			got, err := UnmarshalBGPBaseAttributes(raw)
			if err != nil {
				t.Fatalf("UnmarshalBGPBaseAttributes(%x) error = %v, want nil", raw, err)
			}
			if got.SRv6ServiceMalformed != tt.want {
				t.Errorf("UnmarshalBGPBaseAttributes(%x) SRv6ServiceMalformed = %t, want %t",
					raw, got.SRv6ServiceMalformed, tt.want)
			}
			if (got.BGPPrefixSID != nil) != tt.wantLegacy || (got.PrefixSID != nil) != tt.wantSID {
				t.Errorf("UnmarshalBGPBaseAttributes(%x) bgp_prefix_sid, prefix_sid = %+v, %+v, want published %t, %t",
					raw, got.BGPPrefixSID, got.PrefixSID, tt.wantLegacy, tt.wantSID)
			}
		})
	}
}

// A bad Label-Index length is reported with the rest of the attribute, so that
// the caller can apply the rule of the route's address family (RFC 8669 §3.1).
func TestGetAttrPrefixSIDReturnsTheRestWithTheError(t *testing.T) {
	update := &Update{PathAttributes: []PathAttribute{
		{AttributeType: 40, Attribute: []byte{0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0}},
	}}
	got, err := update.GetAttrPrefixSID()
	if err == nil || got == nil || got.LabelIndex != nil {
		t.Errorf("GetAttrPrefixSID() = %+v, %v, want a result without a Label-Index and an error", got, err)
	}
}

func TestBaseAttributesSRv6ServiceMalformedIsComparedAndPublished(t *testing.T) {
	flagged := &BaseAttributes{SRv6ServiceMalformed: true}
	if equal, diffs := flagged.Equal(&BaseAttributes{}); equal || len(diffs) != 1 {
		t.Errorf("Equal() of differing flags = %t, %q, want false and one difference", equal, diffs)
	}
	for _, want := range []*BaseAttributes{flagged, {}} {
		b, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("json.Marshal(%+v) error = %v, want nil", want, err)
		}
		if published := strings.Contains(string(b), `"srv6_service_malformed":true`); published != want.SRv6ServiceMalformed ||
			published != strings.Contains(string(b), "srv6_service_malformed") {
			t.Errorf("json.Marshal(%+v) = %s, want srv6_service_malformed only when true", want, b)
		}
		got := &BaseAttributes{}
		if err := json.Unmarshal(b, got); err != nil {
			t.Fatalf("json.Unmarshal(%s) error = %v, want nil", b, err)
		}
		if got.SRv6ServiceMalformed != want.SRv6ServiceMalformed {
			t.Errorf("json.Unmarshal(%s) SRv6ServiceMalformed = %t, want %t",
				b, got.SRv6ServiceMalformed, want.SRv6ServiceMalformed)
		}
	}
}
