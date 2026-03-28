package base

import (
	"testing"
)

// Multiple IPv4 routes
var routeData = []byte{
	0x18, 0x0A, 0x00, 0x01, // /24 10.0.1.0
	0x18, 0x0A, 0x00, 0x02, // /24 10.0.2.0
	0x18, 0x0A, 0x00, 0x03, // /24 10.0.3.0
	0x10, 0xC0, 0xA8, // /16 192.168.0.0
	0x20, 0x0A, 0x01, 0x01, 0x01, // /32 10.1.1.1
}

func BenchmarkUnmarshalRoutes(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := UnmarshalRoutes(routeData, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}
