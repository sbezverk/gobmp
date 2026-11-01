package multicast

import (
	"bytes"
	"testing"
)

func TestMulticastPrefixPadding(t *testing.T) {
	for _, pathID := range []bool{false, true} {
		wire := []byte{17, 10, 1, 127}
		if pathID {
			wire = append([]byte{0, 0, 0, 7}, wire...)
		}
		original := bytes.Clone(wire)
		routes, err := UnmarshalMulticastNLRI(wire, pathID)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes.NLRI) != 1 || routes.NLRI[0].Length != 17 || !bytes.Equal(routes.NLRI[0].Prefix, []byte{10, 1, 0}) {
			t.Fatalf("routes = %+v", routes)
		}
		if pathID && routes.NLRI[0].PathID != 7 {
			t.Fatal("PathID changed")
		}
		if !bytes.Equal(wire, original) {
			t.Fatal("multicast input modified")
		}
	}
}
