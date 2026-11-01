package bgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestAS4CapabilityWireLength(t *testing.T) {
	// RFC 6793 §3 fixes capability 65's value length at four octets.
	for _, length := range []int{0, 1, 2, 3, 4, 5, 255} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			value := bytes.Repeat([]byte{1}, length)
			if length == 4 {
				binary.BigEndian.PutUint32(value, 4200000000)
			}
			// Preceding valid capability ensures errors report the actual offset and
			// return no partially decoded capability map.
			wire := append([]byte{2, 0, 65, byte(length)}, value...)
			caps, err := UnmarshalBGPCapability(wire)
			if length != 4 {
				if err == nil || caps != nil {
					t.Fatalf("malformed AS4 accepted: caps=%v error=%v", caps, err)
				}
				for _, want := range []string{"code 65", "offset 2", "need 4 bytes", fmt.Sprintf("have %d", length)} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q missing %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(caps[2]) != 1 || len(caps[65]) != 1 || !bytes.Equal(caps[65][0].Value, value) {
				t.Fatalf("decoded=%+v", caps)
			}
			asn, ok := (&OpenMessage{Capabilities: caps}).Is4BytesASCapable()
			if !ok || asn != 4200000000 {
				t.Fatalf("AS4=(%d,%v)", asn, ok)
			}
		})
	}
	for _, wire := range [][]byte{{65}, {65, 4}, {65, 4, 0, 0, 1}, {2, 0, 65, 4, 0, 0, 1}} {
		if caps, err := UnmarshalBGPCapability(wire); err == nil || caps != nil {
			t.Fatalf("truncated value accepted: %x, %v, %v", wire, caps, err)
		}
	}
}

func TestIs4BytesASCapableFirstEntry(t *testing.T) {
	valid := &CapabilityData{Value: []byte{0xfa, 0x56, 0xea, 0}}
	tests := []struct {
		name    string
		open    *OpenMessage
		want    uint32
		capable bool
	}{
		{name: "nil receiver"},
		{name: "nil map", open: &OpenMessage{}},
		{name: "absent code", open: &OpenMessage{Capabilities: Capability{2: {}}}},
		{name: "nil slice", open: &OpenMessage{Capabilities: Capability{65: nil}}},
		{name: "empty slice", open: &OpenMessage{Capabilities: Capability{65: {}}}},
		{name: "nil first", open: &OpenMessage{Capabilities: Capability{65: {nil, valid}}}},
		{name: "nil value", open: &OpenMessage{Capabilities: Capability{65: {{}, valid}}}},
		{name: "empty value", open: &OpenMessage{Capabilities: Capability{65: {{Value: []byte{}}, valid}}}},
		{name: "short one", open: &OpenMessage{Capabilities: Capability{65: {{Value: []byte{1}}, valid}}}},
		{name: "short two", open: &OpenMessage{Capabilities: Capability{65: {{Value: []byte{1, 2}}, valid}}}},
		{name: "short three", open: &OpenMessage{Capabilities: Capability{65: {{Value: []byte{1, 2, 3}}, valid}}}},
		{name: "valid", open: &OpenMessage{Capabilities: Capability{65: {valid}}}, want: 4200000000, capable: true},
		{name: "first valid wins", open: &OpenMessage{Capabilities: Capability{65: {valid, {Value: []byte{0, 0, 0, 1}}}}}, want: 4200000000, capable: true},
		// Preserve the public getter's established first-four-byte behavior for
		// manually constructed entries; the wire decoder rejects oversized values.
		{name: "oversized manual first", open: &OpenMessage{Capabilities: Capability{65: {{Value: []byte{0xfa, 0x56, 0xea, 0, 99}}}}}, want: 4200000000, capable: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asn, ok := tt.open.Is4BytesASCapable()
			if asn != tt.want || ok != tt.capable {
				t.Fatalf("got (%d,%v), want (%d,%v)", asn, ok, tt.want, tt.capable)
			}
		})
	}
}
