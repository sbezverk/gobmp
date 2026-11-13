package srpolicycp

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func srpcpTLV(typ uint16, value []byte) []byte {
	b := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(value)))
	copy(b[4:], value)
	return b
}

func srpcpU32(value uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, value)
	return b
}

func srpcpNodeDescriptor(routerIDType uint16, routerID []byte) []byte {
	return srpcpTLV(base.LocalNodeDescriptorType, srpcpTLV(routerIDType, routerID))
}

func srpcpAddressBytes(address string) []byte {
	a := netip.MustParseAddr(address)
	if a.Is4() {
		v := a.As4()
		return v[:]
	}
	v := a.As16()
	return v[:]
}

func srpcpDescriptorValue(flags byte) []byte {
	value := []byte{byte(SRPolicyCandidatePathOriginBGPSRPolicy), flags, 0, 0}
	if flags&0x80 != 0 {
		value = append(value, srpcpAddressBytes("2001:db8::1")...)
	} else {
		value = append(value, srpcpAddressBytes("192.0.2.1")...)
	}
	value = append(value, srpcpU32(42)...)
	value = append(value, srpcpU32(65000)...)
	if flags&0x40 != 0 {
		value = append(value, srpcpAddressBytes("2001:db8::2")...)
	} else {
		value = append(value, srpcpAddressBytes("192.0.2.2")...)
	}
	value = append(value, srpcpU32(7)...)
	return value
}

func srpcpDescriptor(flags byte) []byte {
	return srpcpTLV(554, srpcpDescriptorValue(flags))
}

func srpcpNLRI(routerIDType uint16, routerID []byte, descriptor []byte) []byte {
	b := []byte{byte(base.SR)}
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 1) // Domain identifier.
	b = append(b, srpcpNodeDescriptor(routerIDType, routerID)...)
	b = append(b, descriptor...)
	return b
}

func assertNoPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("unexpected panic: %v", recovered)
		}
	}()
	fn()
}

func TestSRPolicyCandidatePathOriginString(t *testing.T) {
	tests := []struct {
		origin SRPolicyCandidatePathOrigin
		want   string
	}{
		{SRPolicyCandidatePathOriginReserved, "Reserved"},
		{SRPolicyCandidatePathOriginPCEP, "PCEP"},
		{SRPolicyCandidatePathOriginBGPSRPolicy, "BGP SR Policy"},
		{SRPolicyCandidatePathOriginConfiguration, "Configuration"},
		{SRPolicyCandidatePathOriginPCEPFromPCE, "PCEP from PCE"},
		{SRPolicyCandidatePathOriginBGPSRPolicyFromPCE, "BGP SR Policy from PCE"},
		{SRPolicyCandidatePathOriginConfigurationFromPCE, "Configuration from PCE"},
		{SRPolicyCandidatePathOrigin(255), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.origin.String(); got != tt.want {
			t.Errorf("origin %d String() = %q, want %q", tt.origin, got, tt.want)
		}
	}
}

func TestSRPolicyCandidatePathFlagsJSONRoundTrip(t *testing.T) {
	for _, want := range []SRPolicyCandidatePathFlags{0, 0x80, 0x40, 0xc0} {
		t.Run(string(rune(want)), func(t *testing.T) {
			encoded, err := json.Marshal(want)
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			var got SRPolicyCandidatePathFlags
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if got != want {
				t.Fatalf("round trip = %#x, want %#x", got, want)
			}
			if got.IsSetE() != (want&0x80 != 0) || got.IsSetO() != (want&0x40 != 0) {
				t.Fatalf("flag helpers for %#x returned E=%t O=%t", want, got.IsSetE(), got.IsSetO())
			}
		})
	}

	var nilFlags *SRPolicyCandidatePathFlags
	if err := nilFlags.UnmarshalJSON([]byte(`{"e_flag":true}`)); err == nil {
		t.Fatal("nil receiver should be rejected")
	}
	got := SRPolicyCandidatePathFlags(0xff)
	if err := got.UnmarshalJSON([]byte(`{"e_flag":true}`)); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got != 0x80 {
		t.Fatalf("UnmarshalJSON() retained unknown bits: got %#x, want %#x", got, 0x80)
	}
	if err := got.UnmarshalJSON([]byte(`{"e_flag":`)); err == nil {
		t.Fatal("invalid JSON returned nil error")
	}
}

func TestUnmarshalSRPCPDescriptorAllFlagLengthForms(t *testing.T) {
	tests := []struct {
		name       string
		flags      byte
		endpoint   string
		originator string
	}{
		{"IPv4 endpoint and originator", 0, "192.0.2.1", "192.0.2.2"},
		{"IPv6 endpoint", 0x80, "2001:db8::1", "192.0.2.2"},
		{"IPv6 originator", 0x40, "192.0.2.1", "2001:db8::2"},
		{"IPv6 endpoint and originator", 0xc0, "2001:db8::1", "2001:db8::2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := append(srpcpTLV(999, []byte{0xde, 0xad}), srpcpDescriptor(tt.flags)...)
			input = append(input, srpcpTLV(1000, nil)...)
			got, err := UnmarshalSRPCPDescriptor(input)
			if err != nil {
				t.Fatalf("UnmarshalSRPCPDescriptor() error = %v", err)
			}
			if got.ProtoOrigin != SRPolicyCandidatePathOriginBGPSRPolicy || got.Flags != SRPolicyCandidatePathFlags(tt.flags) {
				t.Fatalf("origin/flags = %v/%#x, want %v/%#x", got.ProtoOrigin, got.Flags, SRPolicyCandidatePathOriginBGPSRPolicy, tt.flags)
			}
			if got.Endpoint != netip.MustParseAddr(tt.endpoint) || got.OriginatorAddr != netip.MustParseAddr(tt.originator) {
				t.Fatalf("addresses = %s/%s, want %s/%s", got.Endpoint, got.OriginatorAddr, tt.endpoint, tt.originator)
			}
			if got.PolicyColor != 42 || got.OriginatorAS != 65000 || got.Discriminator != 7 {
				t.Fatalf("numeric fields = color %d AS %d discriminator %d, want 42/65000/7", got.PolicyColor, got.OriginatorAS, got.Discriminator)
			}
		})
	}
}

func TestUnmarshalSRPCPDescriptorRejectsMalformedInput(t *testing.T) {
	invalid := []struct {
		name  string
		input []byte
	}{
		{"missing mandatory TLV", srpcpTLV(999, []byte{1})},
		{"truncated TLV header", []byte{0, 1, 0}},
		{"truncated TLV value", []byte{0x02, 0x2a, 0, 24, 1}},
		{"invalid descriptor length", srpcpTLV(554, make([]byte, 25))},
		{"length 24 with E flag", srpcpTLV(554, srpcpDescriptorValue(0x80)[:24])},
		{"length 24 with O flag", srpcpTLV(554, srpcpDescriptorValue(0x40)[:24])},
		{"length 36 with neither flag", srpcpTLV(554, append(srpcpDescriptorValue(0), make([]byte, 12)...))},
		{"length 48 with E only", srpcpTLV(554, append(srpcpDescriptorValue(0x80), make([]byte, 12)...))},
		{"length 48 with O only", srpcpTLV(554, append(srpcpDescriptorValue(0x40), make([]byte, 12)...))},
		{"reserved bytes nonzero", srpcpTLV(554, func() []byte {
			v := srpcpDescriptorValue(0)
			v[2] = 1
			return v
		}())},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			assertNoPanic(t, func() {
				if got, err := UnmarshalSRPCPDescriptor(tt.input); err == nil || got != nil {
					t.Fatalf("decode = %+v, %v; want nil and an error", got, err)
				}
			})
		})
	}
}

func TestUnmarshalSRPCPDescriptorTruncatedNeverPanics(t *testing.T) {
	valid := srpcpDescriptor(0xc0)
	for cut := 0; cut < len(valid); cut++ {
		t.Run(fmt.Sprintf("cut-%d", cut), func(t *testing.T) {
			assertNoPanic(t, func() {
				if got, err := UnmarshalSRPCPDescriptor(valid[:cut]); err == nil || got != nil {
					t.Fatalf("decode = %+v, %v; want nil and an error", got, err)
				}
			})
		})
	}
}

func TestUnmarshalSRPolicyCandidatePathNLRI(t *testing.T) {
	tests := []struct {
		name     string
		routerID uint16
		address  string
	}{
		{"IPv4 local router ID", 1028, "192.0.2.1"},
		{"IPv6 local router ID", 1029, "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := srpcpNodeDescriptor(tt.routerID, srpcpAddressBytes(tt.address))
			input := srpcpNLRI(tt.routerID, srpcpAddressBytes(tt.address), srpcpDescriptor(0))
			got, err := UnmarshalSRPolicyCandidatePathNLRI(input)
			if err != nil {
				t.Fatalf("UnmarshalSRPolicyCandidatePathNLRI() error = %v", err)
			}
			if got.ProtocolID != base.SR || !bytes.Equal(got.Identifier, []byte{0, 0, 0, 0, 0, 0, 0, 1}) {
				t.Fatalf("protocol/identifier = %v/%x", got.ProtocolID, got.Identifier)
			}
			if got.LocalNode == nil || got.Descriptor == nil {
				t.Fatalf("decoded local node or descriptor is nil: %+v", got)
			}
			if got.Descriptor.Endpoint != netip.MustParseAddr("192.0.2.1") {
				t.Errorf("endpoint = %s, want 192.0.2.1", got.Descriptor.Endpoint)
			}
			if tt.routerID == 1028 && !bytes.Equal(got.LocalNode.GetLocalNodeIPv4RouterID(), srpcpAddressBytes(tt.address)) {
				t.Errorf("IPv4 router ID = %x, want %x", got.LocalNode.GetLocalNodeIPv4RouterID(), srpcpAddressBytes(tt.address))
			}
			if tt.routerID == 1029 && !bytes.Equal(got.LocalNode.GetLocalNodeIPv6RouterID(), srpcpAddressBytes(tt.address)) {
				t.Errorf("IPv6 router ID = %x, want %x", got.LocalNode.GetLocalNodeIPv6RouterID(), srpcpAddressBytes(tt.address))
			}
			hash := md5.Sum(node)
			if got.LocalNodeHash != hex.EncodeToString(hash[:]) {
				t.Errorf("LocalNodeHash = %q, want %q", got.LocalNodeHash, hex.EncodeToString(hash[:]))
			}
		})
	}
}

func TestUnmarshalSRPolicyCandidatePathNLRIRejectsMalformedInput(t *testing.T) {
	validNode := srpcpNodeDescriptor(1028, srpcpAddressBytes("192.0.2.1"))
	withoutRouterID := srpcpNodeDescriptor(516, []byte{192, 0, 2, 1})
	validPrefix := append([]byte{byte(base.SR)}, make([]byte, 8)...)
	validPrefix = append(validPrefix, validNode...)
	invalid := []struct {
		name  string
		input []byte
	}{
		{"too short", make([]byte, 12)},
		{"wrong protocol", append([]byte{byte(base.OSPFv2)}, make([]byte, 12)...)},
		{"truncated node descriptor header", append(validPrefix[:9], 1, 0, 0)},
		{"truncated node descriptor value", append(validPrefix[:9], 1, 0, 0, 24, 0)},
		{"malformed node descriptor TLV", append(append([]byte{}, []byte{byte(base.SR)}...), append(make([]byte, 8), append(srpcpTLV(base.LocalNodeDescriptorType, []byte{0, 1, 0}), srpcpDescriptor(0)...)...)...)},
		{"node descriptor has no router ID", append(append([]byte{}, []byte{byte(base.SR)}...), append(make([]byte, 8), append(withoutRouterID, srpcpDescriptor(0)...)...)...)},
		{"missing mandatory descriptor", append(validPrefix, srpcpTLV(999, []byte{1})...)},
		{"malformed mandatory descriptor", append(validPrefix, []byte{0x02, 0x2a, 0, 24, 1}...)},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			assertNoPanic(t, func() {
				if got, err := UnmarshalSRPolicyCandidatePathNLRI(tt.input); err == nil || got != nil {
					t.Fatalf("decode = %+v, %v; want nil and an error", got, err)
				}
			})
		})
	}
}

func TestUnmarshalSRPolicyCandidatePathNLRITruncatedNeverPanics(t *testing.T) {
	valid := srpcpNLRI(1028, srpcpAddressBytes("192.0.2.1"), srpcpDescriptor(0))
	for cut := 0; cut < len(valid); cut++ {
		t.Run(fmt.Sprintf("cut-%d", cut), func(t *testing.T) {
			assertNoPanic(t, func() {
				if got, err := UnmarshalSRPolicyCandidatePathNLRI(valid[:cut]); err == nil || got != nil {
					t.Fatalf("decode = %+v, %v; want nil and an error", got, err)
				}
			})
		})
	}
}

func TestSRPCPDescriptorJSONRoundTrip(t *testing.T) {
	want := SRPCPDescriptor{
		ProtoOrigin:    SRPolicyCandidatePathOriginPCEPFromPCE,
		Flags:          0xc0,
		Endpoint:       netip.MustParseAddr("2001:db8::1"),
		PolicyColor:    42,
		OriginatorAS:   65000,
		OriginatorAddr: netip.MustParseAddr("2001:db8::2"),
		Discriminator:  7,
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got SRPCPDescriptor
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got != want {
		t.Fatalf("JSON round trip = %+v, want %+v", got, want)
	}
}
