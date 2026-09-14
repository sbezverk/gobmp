package base

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

// interASTLV encodes a BGP-LS TLV for test fixtures.
func interASTLV(typ uint16, value []byte) []byte {
	b := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(value)))
	return append(b, value...)
}

// validInterASLinkNLRI builds a complete dual-stack draft-44 NLRI fixture.
func validInterASLinkNLRI() []byte {
	local := append(interASTLV(512, []byte{0, 0, 0xfd, 0xe8}), interASTLV(514, []byte{0, 0, 0, 7})...)
	local = append(local, interASTLV(515, []byte{10, 0, 0, 1})...)
	local = append(local, interASTLV(1028, []byte{192, 0, 2, 1})...)
	local = append(local, interASTLV(1029, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})...)
	localDescriptor := interASTLV(256, local)
	links := append(interASTLV(270, []byte{0, 0, 0xfd, 0xe9}), interASTLV(271, []byte{192, 0, 2, 2})...)
	links = append(links, interASTLV(272, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})...)
	links = append(links, interASTLV(258, []byte{0, 0, 0, 10, 0, 0, 0, 20})...)
	links = append(links, interASTLV(259, []byte{198, 51, 100, 1})...)
	links = append(links, interASTLV(260, []byte{198, 51, 100, 2})...)
	links = append(links, interASTLV(999, []byte{0xaa, 0xbb})...)
	b := []byte{byte(OSPFv2), 0, 0, 0, 0, 0, 0, 0, 42}
	b = append(b, localDescriptor...)
	return append(b, links...)
}

// TestUnmarshalInterASLinkNLRI verifies full decoding, accessor values, hashes, and unknown-TLV retention.
func TestUnmarshalInterASLinkNLRI(t *testing.T) {
	nlri, err := UnmarshalInterASLinkNLRI(validInterASLinkNLRI())
	if err != nil {
		t.Fatalf("UnmarshalInterASLinkNLRI: %v", err)
	}
	if nlri.ProtocolID != OSPFv2 || nlri.GetProtocolID() != "OSPFv2" || nlri.GetIdentifier() != 42 {
		t.Fatalf("unexpected header: protocol=%d description=%q identifier=%d", nlri.ProtocolID, nlri.GetProtocolID(), nlri.GetIdentifier())
	}
	if got := nlri.LocalNode.GetASN(); got != 65000 {
		t.Errorf("local ASN = %d, want 65000", got)
	}
	if got := nlri.GetRemoteASN(); got != 65001 {
		t.Errorf("remote ASN = %d, want 65001", got)
	}
	if key := nlri.GetDomainKey(); key.ASN != 65000 || key.Identifier != 42 {
		t.Errorf("domain key = %+v, want ASN 65000 and identifier 42", key)
	}
	if got := nlri.GetLocalASBRIPv4().String(); got != "192.0.2.1" {
		t.Errorf("local IPv4 ASBR = %q", got)
	}
	if got := nlri.GetLocalASBRIPv6().String(); got != "2001:db8::1" {
		t.Errorf("local IPv6 ASBR = %q", got)
	}
	if got := nlri.GetRemoteASBRIPv4().String(); got != "192.0.2.2" {
		t.Errorf("remote IPv4 ASBR = %q", got)
	}
	if got := nlri.GetRemoteASBRIPv6().String(); got != "2001:db8::2" {
		t.Errorf("remote IPv6 ASBR = %q", got)
	}
	if _, ok := nlri.Link.LinkTLV[999]; !ok {
		t.Error("unknown link descriptor was not preserved")
	}
	if nlri.LocalNodeHash == "" || nlri.LinkHash == "" {
		t.Error("descriptor hashes were not populated")
	}
}

// TestInterASLinkNLRIMissingOptionalValues verifies accessors return safe zero values for absent descriptors.
func TestInterASLinkNLRIMissingOptionalValues(t *testing.T) {
	nlri := &InterASLinkNLRI{
		LocalNode: &NodeDescriptor{SubTLV: map[uint16]TLV{}},
		Link:      &LinkDescriptor{LinkTLV: map[uint16]TLV{}},
	}
	if nlri.GetLocalASBRIPv4() != nil || nlri.GetLocalASBRIPv6() != nil {
		t.Error("missing local ASBR IDs must return nil")
	}
	if nlri.GetRemoteASN() != 0 {
		t.Error("missing remote ASN must return zero")
	}
	if nlri.GetRemoteASBRIPv4() != nil || nlri.GetRemoteASBRIPv6() != nil {
		t.Error("missing remote ASBR IDs must return nil")
	}
}

// TestInterASLinkNLRIIdentifierIsUnsigned verifies the full 64-bit instance identifier is preserved.
func TestInterASLinkNLRIIdentifierIsUnsigned(t *testing.T) {
	b := validInterASLinkNLRI()
	for i := 1; i < 9; i++ {
		b[i] = 0xff
	}
	nlri, err := UnmarshalInterASLinkNLRI(b)
	if err != nil {
		t.Fatalf("UnmarshalInterASLinkNLRI: %v", err)
	}
	if got := nlri.GetIdentifier(); got != ^uint64(0) {
		t.Errorf("identifier = %d, want %d", got, ^uint64(0))
	}
}

// TestInterASDomainKeyIncludesASN verifies equal Instance Identifiers in different ASes remain distinct.
func TestInterASDomainKeyIncludesASN(t *testing.T) {
	first, err := UnmarshalInterASLinkNLRI(validInterASLinkNLRI())
	if err != nil {
		t.Fatalf("first UnmarshalInterASLinkNLRI: %v", err)
	}
	wire := validInterASLinkNLRI()
	binary.BigEndian.PutUint32(wire[17:21], 65002)
	second, err := UnmarshalInterASLinkNLRI(wire)
	if err != nil {
		t.Fatalf("second UnmarshalInterASLinkNLRI: %v", err)
	}
	if *first.GetDomainKey() == *second.GetDomainKey() {
		t.Fatalf("domain keys must differ: first=%+v second=%+v", first.GetDomainKey(), second.GetDomainKey())
	}
	if first.GetIdentifier() != second.GetIdentifier() {
		t.Fatalf("identifiers differ: first=%d second=%d", first.GetIdentifier(), second.GetIdentifier())
	}
}

// TestUnmarshalInterASLinkNLRIProtocolIDs verifies Direct and Static sources are accepted from the wire.
func TestUnmarshalInterASLinkNLRIProtocolIDs(t *testing.T) {
	for _, protocol := range []ProtoID{Direct, Static} {
		t.Run(ProtocolIDString(protocol), func(t *testing.T) {
			wire := validInterASLinkNLRI()
			wire[0] = byte(protocol)
			localLength := binary.BigEndian.Uint16(wire[11:13])
			binary.BigEndian.PutUint16(wire[11:13], localLength-8)
			wire = append(append([]byte(nil), wire[:21]...), wire[29:]...)
			nlri, err := UnmarshalInterASLinkNLRI(wire)
			if err != nil {
				t.Fatalf("UnmarshalInterASLinkNLRI: %v", err)
			}
			if nlri.ProtocolID != protocol {
				t.Errorf("Protocol-ID = %d, want %d", nlri.ProtocolID, protocol)
			}
		})
	}
}

// TestInterASRemoteASNUsesFourOctets verifies draft-44 accepts the full 32-bit ASN value.
func TestInterASRemoteASNUsesFourOctets(t *testing.T) {
	wire := validInterASLinkNLRI()
	localLength := int(binary.BigEndian.Uint16(wire[11:13]))
	remoteASValue := 13 + localLength + 4
	binary.BigEndian.PutUint32(wire[remoteASValue:remoteASValue+4], 4200000000)
	nlri, err := UnmarshalInterASLinkNLRI(wire)
	if err != nil {
		t.Fatalf("UnmarshalInterASLinkNLRI: %v", err)
	}
	if got := nlri.GetRemoteASN(); got != 4200000000 {
		t.Errorf("remote ASN = %d, want 4200000000", got)
	}
}

// TestUnmarshalInterASLinkNLRIMandatoryFields exercises malformed and missing mandatory descriptor handling.
func TestUnmarshalInterASLinkNLRIMandatoryFields(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{name: "short", input: []byte{3}, wantErr: "too short"},
		{name: "wrong node descriptor type", input: func() []byte {
			b := validInterASLinkNLRI()
			binary.BigEndian.PutUint16(b[9:11], 257)
			return b
		}(), wantErr: "expected 256"},
		{name: "missing local AS", input: func() []byte {
			b := validInterASLinkNLRI()
			localLength := binary.BigEndian.Uint16(b[11:13])
			binary.BigEndian.PutUint16(b[11:13], localLength-8)
			return append(append([]byte(nil), b[:13]...), b[21:]...)
		}(), wantErr: "missing Autonomous System"},
		{name: "missing IGP router ID", input: func() []byte {
			b := validInterASLinkNLRI()
			localLength := binary.BigEndian.Uint16(b[11:13])
			binary.BigEndian.PutUint16(b[11:13], localLength-8)
			return append(append([]byte(nil), b[:29]...), b[37:]...)
		}(), wantErr: "missing IGP Router-ID"},
		{name: "missing local ASBR", input: func() []byte {
			b := validInterASLinkNLRI()
			localLength := binary.BigEndian.Uint16(b[11:13])
			binary.BigEndian.PutUint16(b[11:13], localLength-28)
			return append(append([]byte(nil), b[:37]...), b[65:]...)
		}(), wantErr: "missing IPv4 or IPv6 ASBR"},
		{name: "malformed local descriptor", input: func() []byte {
			b := validInterASLinkNLRI()
			binary.BigEndian.PutUint16(b[15:17], 0xffff)
			return b
		}(), wantErr: "invalid Inter-AS Link Local Node Descriptor"},
		{name: "no link descriptors", input: func() []byte {
			b := validInterASLinkNLRI()
			localLength := int(binary.BigEndian.Uint16(b[11:13]))
			return b[:13+localLength]
		}(), wantErr: "no link descriptors"},
		{name: "malformed link descriptors", input: func() []byte {
			b := validInterASLinkNLRI()
			return b[:len(b)-1]
		}(), wantErr: "invalid Inter-AS Link Descriptors"},
		{name: "missing remote AS", input: func() []byte {
			b := validInterASLinkNLRI()
			localLength := int(binary.BigEndian.Uint16(b[11:13]))
			p := 13 + localLength
			return append(append([]byte(nil), b[:p]...), b[p+8:]...)
		}(), wantErr: "missing Remote AS Number"},
		{name: "missing remote ASBR", input: func() []byte {
			b := validInterASLinkNLRI()
			localLength := int(binary.BigEndian.Uint16(b[11:13]))
			p := 13 + localLength
			return append(append([]byte(nil), b[:p+8]...), b[p+36:]...)
		}(), wantErr: "missing IPv4 or IPv6 Remote ASBR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalInterASLinkNLRI(tt.input)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// TestValidateInterASLocalNodeISIS verifies IS-IS IDs and rejects the OSPF-only Area-ID descriptor.
func TestValidateInterASLocalNodeISIS(t *testing.T) {
	node := &NodeDescriptor{SubTLV: map[uint16]TLV{
		512:  {Type: 512, Length: 4, Value: []byte{0, 0, 0xfd, 0xe8}},
		515:  {Type: 515, Length: 6, Value: []byte{1, 2, 3, 4, 5, 6}},
		1028: {Type: 1028, Length: 4, Value: []byte{192, 0, 2, 1}},
	}}
	if err := validateInterASLocalNode(node, ISISL2); err != nil {
		t.Fatalf("validateInterASLocalNode: %v", err)
	}
	node.SubTLV[514] = TLV{Type: 514, Length: 4, Value: []byte{0, 0, 0, 1}}
	if err := validateInterASLocalNode(node, ISISL2); err == nil || !strings.Contains(err.Error(), "non-OSPF") {
		t.Fatalf("expected non-OSPF Area-ID error, got %v", err)
	}
}

// TestUnmarshalInterASLinkNLRIFixedLengths verifies every fixed-width descriptor rejects invalid lengths.
func TestUnmarshalInterASLinkNLRIFixedLengths(t *testing.T) {
	tests := []struct {
		typ    uint16
		value  []byte
		oldLen int
	}{
		{typ: 512, value: []byte{1, 2}, oldLen: 4},
		{typ: 514, value: []byte{1, 2}, oldLen: 4},
		{typ: 515, value: []byte{1, 2}, oldLen: 4},
		{typ: 1028, value: []byte{1, 2}, oldLen: 4},
		{typ: 1029, value: []byte{1, 2}, oldLen: 16},
		{typ: 258, value: []byte{1, 2}, oldLen: 8},
		{typ: 270, value: []byte{1, 2}, oldLen: 4},
		{typ: 271, value: []byte{1, 2}, oldLen: 4},
		{typ: 272, value: []byte{1, 2}, oldLen: 16},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(int(tt.typ)), func(t *testing.T) {
			b := validInterASLinkNLRI()
			needle := interASTLV(tt.typ, make([]byte, tt.oldLen))
			for i := range b {
				if i+len(needle) <= len(b) && binary.BigEndian.Uint16(b[i:i+2]) == tt.typ && int(binary.BigEndian.Uint16(b[i+2:i+4])) == tt.oldLen {
					replacement := interASTLV(tt.typ, tt.value)
					b = append(append(append([]byte(nil), b[:i]...), replacement...), b[i+len(needle):]...)
					if tt.typ == 512 || tt.typ == 514 || tt.typ == 515 || tt.typ == 1028 || tt.typ == 1029 {
						localLength := binary.BigEndian.Uint16(b[11:13])
						binary.BigEndian.PutUint16(b[11:13], localLength-uint16(tt.oldLen-len(tt.value)))
					}
					break
				}
			}
			_, err := UnmarshalInterASLinkNLRI(b)
			if err == nil || !strings.Contains(err.Error(), "expected") {
				t.Fatalf("expected fixed-length validation error, got %v", err)
			}
		})
	}
}
