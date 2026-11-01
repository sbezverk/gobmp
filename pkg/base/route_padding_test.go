package base

import (
	"bytes"
	"testing"
)

func TestRoutesPrefixPaddingOwnership(t *testing.T) {
	for _, tt := range []struct {
		name       string
		wire, want []byte
	}{
		{"default", []byte{0}, []byte{}},
		{"partial", []byte{17, 10, 1, 127}, []byte{10, 1, 0}},
		{"boundary", []byte{8, 10}, []byte{10}},
		{"ipv6", []byte{65, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 255}, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 128}},
		{"truncated", []byte{17, 10}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			original := bytes.Clone(tt.wire)
			routes, err := UnmarshalRoutes(tt.wire, false)
			if tt.want == nil {
				if err == nil {
					t.Fatal("expected truncation error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(routes) != 1 || !bytes.Equal(routes[0].Prefix, tt.want) {
				t.Fatalf("routes = %+v, want prefix %x", routes, tt.want)
			}
			if len(routes[0].Prefix) > 0 {
				routes[0].Prefix[0] ^= 255
			}
			if !bytes.Equal(tt.wire, original) {
				t.Fatal("prefix aliases input")
			}
		})
	}
}

func TestPrefixDescriptorPadding(t *testing.T) {
	for _, ipv4 := range []bool{true, false} {
		wire := []byte{17, 10, 1, 127}
		descriptor := &PrefixDescriptor{PrefixTLV: map[uint16]TLV{265: {Type: 265, Length: uint16(len(wire)), Value: wire}}}
		route := descriptor.GetPrefixIPReachability(ipv4)
		size := 16
		if ipv4 {
			size = 4
		}
		want := make([]byte, size)
		copy(want, []byte{10, 1})
		if route == nil || route.Length != 17 || !bytes.Equal(route.Prefix, want) {
			t.Fatalf("ipv4=%v: route = %+v, want prefix %x", ipv4, route, want)
		}
		if !bytes.Equal(wire, []byte{17, 10, 1, 127}) {
			t.Fatal("descriptor input modified")
		}
	}
}
