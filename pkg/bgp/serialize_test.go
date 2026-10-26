package bgp_test

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

func serializationOpen() *bgp.OpenMessage {
	return &bgp.OpenMessage{Version: 4, MyAS: 65000, HoldTime: 90, BGPID: []byte{192, 0, 2, 1}}
}

func TestSerializeOpenSemanticRoundTrip(t *testing.T) {
	o := serializationOpen()
	o.Length = 1
	o.Type = 99
	o.OptParamLen = 99
	o.OptionalParameters = []bgp.InformationalTLV{{Type: 100, Length: 99, Value: []byte{1, 2}}}
	o.Capabilities = bgp.Capability{65: []*bgp.CapabilityData{{Value: []byte{0, 0, 0xfd, 0xe8}}}, 1: []*bgp.CapabilityData{{Value: []byte{0, 1, 0, 1}}, {Value: []byte{0, 2, 0, 1}}}}
	before := *o
	frame, err := o.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame[:16], bytes.Repeat([]byte{255}, 16)) || int(binary.BigEndian.Uint16(frame[16:18])) != len(frame) || frame[18] != 1 {
		t.Fatalf("bad header: %x", frame)
	}
	parsed, err := bgp.UnmarshalBGPOpenMessage(frame[16:])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Capabilities[1]) != 2 || len(parsed.Capabilities[65]) != 1 || !reflect.DeepEqual(parsed.OptionalParameters[0].Value, []byte{1, 2}) {
		t.Fatalf("lost fields: %+v", parsed)
	}
	again, err := parsed.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame, again) {
		t.Fatal("non-deterministic OPEN")
	}
	if !reflect.DeepEqual(before, *o) {
		t.Fatal("receiver mutated")
	}
	frame[24] = 99
	if o.BGPID[0] != 192 {
		t.Fatal("output aliases receiver")
	}
}

func TestSerializeOpenRFC9072(t *testing.T) {
	for _, n := range []int{252, 253, 254, 255, 256, 1024} {
		o := serializationOpen()
		o.OptionalParameters = []bgp.InformationalTLV{{Type: 100, Value: bytes.Repeat([]byte{7}, n)}}
		frame, err := o.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		// The first three cases have ordinary totals of exactly 254, 255,
		// and 256 bytes. Total 255 uses OptParamLen=255 without a sentinel;
		// RFC 9072 is distinguished by the following reserved type byte.
		ordinaryTotal := n + 2
		extended := ordinaryTotal > 255
		hasSentinel := frame[28] == 255 && frame[29] == 255
		if hasSentinel != extended {
			t.Fatalf("ordinary total=%d: sentinel=%t, want %t", ordinaryTotal, hasSentinel, extended)
		}
		if extended {
			if int(binary.BigEndian.Uint16(frame[30:32])) != n+3 || frame[32] != 100 || int(binary.BigEndian.Uint16(frame[33:35])) != n || len(frame) != 35+n {
				t.Fatalf("invalid extended wire encoding for ordinary total %d", ordinaryTotal)
			}
		} else {
			if int(frame[28]) != ordinaryTotal || frame[29] != 100 || int(frame[30]) != n || len(frame) != 31+n {
				t.Fatalf("invalid ordinary wire encoding for total %d", ordinaryTotal)
			}
		}
		parsed, err := bgp.UnmarshalBGPOpenMessage(frame[16:])
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.OptionalParameters) != 1 || len(parsed.OptionalParameters[0].Value) != n {
			t.Fatal("lost extended parameter")
		}
		again, err := parsed.Serialize()
		if err != nil || !bytes.Equal(frame, again) {
			t.Fatalf("OPEN boundary roundtrip: %v", err)
		}
	}
	// Capabilities retain one-byte value lengths even in extended OPEN encoding.
	o := serializationOpen()
	o.Capabilities = bgp.Capability{200: []*bgp.CapabilityData{{Value: make([]byte, 255)}}}
	b, err := o.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := bgp.UnmarshalBGPOpenMessage(b[16:])
	if err != nil || len(parsed.Capabilities[200][0].Value) != 255 {
		t.Fatalf("large capability: %v", err)
	}
}

func TestSerializeUpdateRoundTripAndBoundaries(t *testing.T) {
	for _, n := range []int{0, 255, 256, 4000} {
		u := &bgp.Update{WithdrawnRoutesLength: 99, TotalPathAttributeLength: 99, WithdrawnRoutes: []byte{8, 10}, PathAttributes: []bgp.PathAttribute{{AttributeTypeFlags: 0x80, AttributeType: 200, AttributeLength: 99, Attribute: make([]byte, n)}}}
		before := *u
		frame, err := u.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if int(binary.BigEndian.Uint16(frame[16:18])) != len(frame) || frame[18] != 2 {
			t.Fatal("bad BGP header")
		}
		parsed, err := bgp.UnmarshalBGPUpdate(frame[19:])
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.PathAttributes) != 1 || len(parsed.PathAttributes[0].Attribute) != n || !bytes.Equal(parsed.WithdrawnRoutes, u.WithdrawnRoutes) {
			t.Fatal("raw fields lost")
		}
		if (parsed.PathAttributes[0].AttributeTypeFlags&0x10 != 0) != (n > 255) {
			t.Fatal("extended length flag not derived")
		}
		again, err := parsed.Serialize()
		if err != nil || !bytes.Equal(frame, again) {
			t.Fatalf("round trip: %v", err)
		}
		if !reflect.DeepEqual(before, *u) {
			t.Fatal("receiver mutated")
		}
		frame[21] = 99
		if u.WithdrawnRoutes[0] != 8 {
			t.Fatal("output aliases input")
		}
	}
	// Parsed empty updates carry a nonnil cache and an MD5 hash. Neither is a
	// semantic wire attribute, including empty nonnil containers supplied by users.
	for _, withdraw := range [][]byte{nil, {8, 10}} {
		frame, err := (&bgp.Update{WithdrawnRoutes: withdraw}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := bgp.UnmarshalBGPUpdate(frame[19:])
		if err != nil {
			t.Fatal(err)
		}
		parsed.BaseAttributes.ASPath = []uint32{}
		parsed.BaseAttributes.UnknownAttributes = []bgp.UnknownPathAttribute{}
		again, err := parsed.Serialize()
		if err != nil || !bytes.Equal(frame, again) {
			t.Fatalf("EOR/withdraw-only: %v", err)
		}
	}
	// Raw MP_REACH/ADD-PATH/unknown-NLRI data is transported, not synthesized.
	mp := []byte{0, 1, 1, 4, 192, 0, 2, 1, 0, 0, 0, 0, 7, 8, 10}
	u := &bgp.Update{PathAttributes: []bgp.PathAttribute{{AttributeTypeFlags: 0x80, AttributeType: 14, Attribute: mp}}}
	frame, err := u.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := bgp.UnmarshalBGPUpdate(frame[19:])
	if err != nil || !bytes.Equal(parsed.PathAttributes[0].Attribute, mp) {
		t.Fatalf("MP raw bytes changed: %v", err)
	}
}

func TestSerializeBGPRejectsInvalidInputs(t *testing.T) {
	cases := []func() ([]byte, error){
		func() ([]byte, error) { return (*bgp.OpenMessage)(nil).Serialize() },
		func() ([]byte, error) { return (&bgp.OpenMessage{}).Serialize() },
		func() ([]byte, error) { o := serializationOpen(); o.HoldTime = 1; return o.Serialize() },
		func() ([]byte, error) { o := serializationOpen(); o.BGPID = make([]byte, 4); return o.Serialize() },
		func() ([]byte, error) { o := serializationOpen(); o.BGPID = []byte{1}; return o.Serialize() },
		func() ([]byte, error) {
			o := serializationOpen()
			o.OptionalParameters = []bgp.InformationalTLV{{Type: 2}}
			o.Capabilities = bgp.Capability{65: []*bgp.CapabilityData{{Value: make([]byte, 4)}}}
			return o.Serialize()
		},
		func() ([]byte, error) {
			o := serializationOpen()
			o.Capabilities = bgp.Capability{65: []*bgp.CapabilityData{nil}}
			return o.Serialize()
		},
		func() ([]byte, error) {
			o := serializationOpen()
			o.Capabilities = bgp.Capability{65: []*bgp.CapabilityData{{Value: make([]byte, 3)}}}
			return o.Serialize()
		},
		func() ([]byte, error) {
			o := serializationOpen()
			o.Capabilities = bgp.Capability{200: []*bgp.CapabilityData{{Value: make([]byte, 256)}}}
			return o.Serialize()
		},
		func() ([]byte, error) {
			o := serializationOpen()
			o.OptionalParameters = []bgp.InformationalTLV{{Type: 2, Value: []byte{65, 4, 0}}}
			return o.Serialize()
		},
		func() ([]byte, error) {
			o := serializationOpen()
			o.OptionalParameters = []bgp.InformationalTLV{{Type: 100, Value: make([]byte, 4096)}}
			return o.Serialize()
		},
		func() ([]byte, error) {
			o := serializationOpen()
			o.OptionalParameters = []bgp.InformationalTLV{{Type: 100, Value: make([]byte, 65536)}}
			return o.Serialize()
		},
		func() ([]byte, error) { return (*bgp.Update)(nil).Serialize() },
		func() ([]byte, error) {
			return (&bgp.Update{BaseAttributes: &bgp.BaseAttributes{Origin: "igp"}}).Serialize()
		},
		func() ([]byte, error) {
			return (&bgp.Update{BaseAttributes: &bgp.BaseAttributes{ASPath: []uint32{65000}}}).Serialize()
		},
		func() ([]byte, error) { return (&bgp.Update{WithdrawnRoutes: make([]byte, 4096)}).Serialize() },
		func() ([]byte, error) { return (&bgp.Update{NLRI: make([]byte, 4096)}).Serialize() },
		func() ([]byte, error) {
			return (&bgp.Update{PathAttributes: []bgp.PathAttribute{{AttributeTypeFlags: 0x80, AttributeType: 200, Attribute: make([]byte, 4070)}}}).Serialize()
		},
		func() ([]byte, error) {
			return (&bgp.Update{PathAttributes: []bgp.PathAttribute{{AttributeTypeFlags: 0x80, AttributeType: 200, Attribute: make([]byte, 65536)}}}).Serialize()
		},
		func() ([]byte, error) {
			return (&bgp.Update{PathAttributes: []bgp.PathAttribute{{AttributeTypeFlags: 1, AttributeType: 200}}}).Serialize()
		},
		func() ([]byte, error) {
			return (&bgp.Update{PathAttributes: []bgp.PathAttribute{{AttributeTypeFlags: 0x40, AttributeType: 1, Attribute: []byte{3}}}}).Serialize()
		},
	}
	for i, f := range cases {
		if b, err := f(); err == nil || b != nil {
			t.Errorf("case %d: %x %v", i, b, err)
		}
	}
}

func TestSerializeBGP4096Limit(t *testing.T) {
	o := serializationOpen()
	// 19-byte header + 10-byte OPEN body + 3-byte RFC9072 envelope +
	// 3-byte parameter header + value = 4096.
	o.OptionalParameters = []bgp.InformationalTLV{{Type: 100, Value: make([]byte, 4061)}}
	b, err := o.Serialize()
	if err != nil || len(b) != 4096 {
		t.Fatalf("OPEN limit: %d %v", len(b), err)
	}
	o.OptionalParameters[0].Value = make([]byte, 4062)
	if _, err = o.Serialize(); err == nil {
		t.Fatal("accepted oversized OPEN")
	}
	u := &bgp.Update{PathAttributes: []bgp.PathAttribute{{AttributeType: 200, AttributeTypeFlags: 0x80, Attribute: make([]byte, 4069)}}}
	b, err = u.Serialize()
	if err != nil || len(b) != 4096 {
		t.Fatalf("UPDATE limit: %d %v", len(b), err)
	}
	u.PathAttributes[0].Attribute = make([]byte, 4070)
	if _, err = u.Serialize(); err == nil {
		t.Fatal("accepted oversized UPDATE")
	}
}

func FuzzSerializeUpdate(f *testing.F) {
	f.Add(byte(200), byte(0x80), []byte{1, 2, 3})
	f.Add(byte(2), byte(0x40), []byte{2, 1, 0xfd, 0xe8})
	f.Add(byte(1), byte(0x40), []byte{})
	f.Fuzz(func(t *testing.T, typ, flags byte, value []byte) {
		if len(value) > 8192 {
			return
		}
		u := &bgp.Update{PathAttributes: []bgp.PathAttribute{{AttributeType: typ, AttributeTypeFlags: flags, Attribute: value}}}
		frame, err := u.Serialize()
		if err != nil {
			return
		}
		if len(frame) > 4096 || int(binary.BigEndian.Uint16(frame[16:18])) != len(frame) {
			t.Fatal("invalid frame size")
		}
		if _, err := bgp.UnmarshalBGPUpdate(frame[19:]); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSerializeOpenRejectsReservedOptionalParameter(t *testing.T) {
	// RFC 9072 sections 2–3 reserve optional parameter type 255 for the
	// extended-length sentinel. It is never an ordinary user parameter,
	// regardless of whether the other parameters require extended encoding.
	for _, n := range []int{0, 252, 253, 254, 256} {
		o := serializationOpen()
		o.OptionalParameters = []bgp.InformationalTLV{{Type: 255, Value: make([]byte, n)}}
		if frame, err := o.Serialize(); err == nil || frame != nil {
			t.Fatalf("type 255 value length %d: got %x, %v", n, frame, err)
		}
	}
}
