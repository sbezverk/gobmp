package base

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

func interASTLV(typ uint16, value []byte) []byte {
	b := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(value)))
	return append(b, value...)
}

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
		{name: "missing local ASBR", input: func() []byte {
			b := validInterASLinkNLRI()
			localLength := binary.BigEndian.Uint16(b[11:13])
			binary.BigEndian.PutUint16(b[11:13], localLength-28)
			return append(append([]byte(nil), b[:37]...), b[65:]...)
		}(), wantErr: "missing IPv4 or IPv6 ASBR"},
		{name: "no link descriptors", input: func() []byte {
			b := validInterASLinkNLRI()
			localLength := int(binary.BigEndian.Uint16(b[11:13]))
			return b[:13+localLength]
		}(), wantErr: "no link descriptors"},
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

func TestUnmarshalInterASLinkNLRIFixedLengths(t *testing.T) {
	tests := []struct {
		typ    uint16
		value  []byte
		oldLen int
	}{
		{typ: 514, value: []byte{1, 2}, oldLen: 4},
		{typ: 515, value: []byte{1, 2}, oldLen: 4},
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
					if tt.typ == 514 || tt.typ == 515 {
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
