package base

import (
	"bytes"
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
	links := append(interASTLV(258, []byte{0, 0, 0, 10, 0, 0, 0, 20}), interASTLV(259, []byte{198, 51, 100, 1})...)
	links = append(links, interASTLV(260, []byte{198, 51, 100, 2})...)
	links = append(links, interASTLV(270, []byte{0, 0, 0xfd, 0xe9})...)
	links = append(links, interASTLV(271, []byte{192, 0, 2, 2})...)
	links = append(links, interASTLV(272, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})...)
	links = append(links, interASTLV(999, []byte{0x01})...)
	links = append(links, interASTLV(999, []byte{0xaa, 0xbb})...)
	b := []byte{byte(OSPFv2), 0, 0, 0, 0, 0, 0, 0, 42}
	b = append(b, localDescriptor...)
	return append(b, links...)
}

// removeInterASLinkTLV removes the first matching link descriptor from a test NLRI.
func removeInterASLinkTLV(b []byte, typ uint16) []byte {
	localLength := int(binary.BigEndian.Uint16(b[11:13]))
	for p := 13 + localLength; p+4 <= len(b); {
		length := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		if binary.BigEndian.Uint16(b[p:p+2]) == typ {
			return append(append([]byte(nil), b[:p]...), b[p+4+length:]...)
		}
		p += 4 + length
	}
	return b
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
	unknown := nlri.Link.GetAll(999)
	if len(unknown) != 2 || !bytes.Equal(unknown[0].Value, []byte{0x01}) || !bytes.Equal(unknown[1].Value, []byte{0xaa, 0xbb}) {
		t.Errorf("duplicate unknown descriptors were not preserved in order: %+v", unknown)
	}
	if nlri.LocalNodeHash == "" || nlri.LinkHash == "" {
		t.Error("descriptor hashes were not populated")
	}
}

// TestInterASLinkNLRIMissingOptionalValues verifies accessors return safe zero values for nil and absent descriptors.
func TestInterASLinkNLRIMissingOptionalValues(t *testing.T) {
	var nilReceiver *InterASLinkNLRI
	tests := map[string]*InterASLinkNLRI{
		"nil receiver": nilReceiver,
		"empty":        {},
		"explicit nil": {LocalNode: nil, Link: nil},
		"empty descriptors": {
			LocalNode: &NodeDescriptor{SubTLV: map[uint16]TLV{}},
			Link:      &InterASLinkDescriptors{},
		},
	}
	for name, nlri := range tests {
		t.Run(name, func(t *testing.T) {
			if nlri.GetProtocolID() != "Unknown" || nlri.GetIdentifier() != 0 {
				t.Errorf("unexpected identity values for %#v", nlri)
			}
			key := nlri.GetDomainKey()
			if nlri == nil || nlri.LocalNode == nil {
				if key != nil {
					t.Errorf("domain key = %+v, want nil", key)
				}
			} else if key == nil || key.ASN != 0 || key.Identifier != 0 {
				t.Errorf("domain key = %+v, want zero-value tuple", key)
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
		})
	}
}

// TestInterASLinkNLRIIdentifierUsesInt64 verifies identifiers match the representation used by other LS types.
func TestInterASLinkNLRIIdentifierUsesInt64(t *testing.T) {
	b := validInterASLinkNLRI()
	for i := 1; i < 9; i++ {
		b[i] = 0xff
	}
	nlri, err := UnmarshalInterASLinkNLRI(b)
	if err != nil {
		t.Fatalf("UnmarshalInterASLinkNLRI: %v", err)
	}
	if got := nlri.GetIdentifier(); got != -1 {
		t.Errorf("identifier = %d, want -1", got)
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
	remoteASValue := 13 + localLength + 12 + 8 + 8 + 4
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
		{name: "non-canonical local descriptor", input: func() []byte {
			b := validInterASLinkNLRI()
			wire := append(append([]byte(nil), b[:13]...), b[21:29]...)
			wire = append(wire, b[13:21]...)
			return append(wire, b[29:]...)
		}(), wantErr: "ordering"},
		{name: "no link descriptors", input: func() []byte {
			b := validInterASLinkNLRI()
			localLength := int(binary.BigEndian.Uint16(b[11:13]))
			return b[:13+localLength]
		}(), wantErr: "no link descriptors"},
		{name: "descriptor before local node", input: func() []byte {
			b := validInterASLinkNLRI()
			localLength := int(binary.BigEndian.Uint16(b[11:13]))
			p := 13 + localLength
			wire := append(append([]byte(nil), b[:p]...), interASTLV(100, []byte{1})...)
			return append(wire, b[p:]...)
		}(), wantErr: "after Local Node Descriptor"},
		{name: "malformed link descriptors", input: func() []byte {
			b := validInterASLinkNLRI()
			return b[:len(b)-1]
		}(), wantErr: "invalid Inter-AS Link Descriptors"},
		{name: "missing remote AS", input: removeInterASLinkTLV(validInterASLinkNLRI(), 270), wantErr: "missing Remote AS Number"},
		{name: "missing remote ASBR", input: removeInterASLinkTLV(removeInterASLinkTLV(validInterASLinkNLRI(), 271), 272), wantErr: "missing IPv4 or IPv6 Remote ASBR"},
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

// TestUnmarshalInterASLinkDescriptorOrdering verifies RFC 9552 canonical ordering is enforced.
func TestUnmarshalInterASLinkDescriptorOrdering(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
	}{
		{
			name: "type",
			wire: append(interASTLV(270, []byte{0, 0, 0, 1}), interASTLV(258, make([]byte, 8))...),
		},
		{
			name: "duplicate length",
			wire: append(interASTLV(999, []byte{1, 2}), interASTLV(999, []byte{1})...),
		},
		{
			name: "duplicate value",
			wire: append(interASTLV(999, []byte{2}), interASTLV(999, []byte{1})...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := UnmarshalInterASLinkDescriptors(tt.wire); err == nil || !strings.Contains(err.Error(), "canonical") {
				t.Fatalf("expected canonical ordering error, got %v", err)
			}
		})
	}
}

// TestUnmarshalInterASLinkDescriptorsMalformed verifies dedicated parsing rejects truncated headers and values.
func TestUnmarshalInterASLinkDescriptorsMalformed(t *testing.T) {
	for _, wire := range [][]byte{{0}, {0, 1, 0}, {0, 1, 0, 2, 1}} {
		if _, err := UnmarshalInterASLinkDescriptors(wire); err == nil {
			t.Fatalf("expected malformed descriptor error for %v", wire)
		}
	}
}

// TestInterASLinkDescriptorAccessorsNil verifies descriptor accessors are safe on nil and malformed values.
func TestInterASLinkDescriptorAccessorsNil(t *testing.T) {
	var descriptors *InterASLinkDescriptors
	if descriptors.GetAll(999) != nil || descriptors.GetLinkIPv4InterfaceAddr() != nil || descriptors.GetLinkIPv4NeighborAddr() != nil || descriptors.GetLinkIPv6InterfaceAddr() != nil || descriptors.GetLinkIPv6NeighborAddr() != nil || descriptors.GetLinkMTID() != nil {
		t.Error("nil descriptor accessors returned values")
	}
	if _, err := descriptors.GetLinkID(); err == nil {
		t.Error("nil descriptors returned a link ID")
	}
	malformed := &InterASLinkDescriptors{TLVs: []TLV{{Type: 258, Length: 2, Value: []byte{1, 2}}}}
	if _, err := malformed.GetLinkID(); err == nil {
		t.Error("malformed TLV 258 returned a link ID")
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

// TestValidateInterASDescriptorsNil verifies internal validators return errors instead of dereferencing nil pointers.
func TestValidateInterASDescriptorsNil(t *testing.T) {
	if err := validateInterASLocalNode(nil, OSPFv2); err == nil {
		t.Error("validateInterASLocalNode(nil) returned nil")
	}
	if err := validateInterASLinkDescriptors(nil); err == nil {
		t.Error("validateInterASLinkDescriptors(nil) returned nil")
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
