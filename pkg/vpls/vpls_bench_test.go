package vpls

import (
	"testing"
)

// BenchmarkUnmarshalRFC4761NLRI benchmarks RFC 4761 NLRI parsing
func BenchmarkUnmarshalRFC4761NLRI(b *testing.B) {
	// Sample RFC 4761 NLRI (17 bytes)
	nlri := []byte{
		0x00, 0x11, // Length: 17
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, // RD Type 0
		0x00, 0x01, // VE ID: 1
		0x00, 0x00, // VE Block Offset: 0
		0x00, 0x0a, // VE Block Size: 10
		0x18, 0x6a, 0x00, // Label Base: 100,000
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnmarshalVPLSNLRI(nlri)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnmarshalRFC6074NLRI benchmarks RFC 6074 NLRI parsing
func BenchmarkUnmarshalRFC6074NLRI(b *testing.B) {
	// Sample RFC 6074 NLRI (12 bytes)
	nlri := []byte{
		0x00, 0x0c, // Length: 12
		0x00, 0x02, 0x00, 0x00, 0xfd, 0xe8, 0x00, 0x64, // RD Type 2
		0x0a, 0x00, 0x00, 0x03, // PE Address: 10.0.0.3
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnmarshalVPLSNLRI(nlri)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnmarshalVPLSNLRI_Mixed benchmarks mixed RFC 4761 + RFC 6074 NLRIs
func BenchmarkUnmarshalVPLSNLRI_Mixed(b *testing.B) {
	// Mixed NLRI: RFC 4761 (17 bytes) + RFC 6074 (12 bytes)
	nlri := []byte{
		// RFC 4761 NLRI
		0x00, 0x11,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x0a,
		0x18, 0x6a, 0x00,
		// RFC 6074 NLRI
		0x00, 0x0c,
		0x00, 0x02, 0x00, 0x00, 0xfd, 0xe8, 0x00, 0x64,
		0x0a, 0x00, 0x00, 0x03,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnmarshalVPLSNLRI(nlri)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseLayer2InfoExtComm benchmarks Layer2 Info Extended Community parsing
func BenchmarkParseLayer2InfoExtComm(b *testing.B) {
	// Sample Layer2 Info Extended Community
	ec := []byte{
		0x80, 0x0a, // Type: Layer2 Info
		0x04,       // Encap: Ethernet
		0x01,       // Flags: C flag
		0x05, 0xdc, // MTU: 1500
		0x00, 0x00, // Reserved
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseLayer2InfoExtComm(ec)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseRouteTarget benchmarks Route Target Extended Community parsing
func BenchmarkParseRouteTarget(b *testing.B) {
	// Sample Route Target (Type 0x0002 - 2-octet AS Specific)
	rt := []byte{
		0x00, 0x02, // Type: 2-octet AS Specific
		0xfd, 0xe8, // AS: 65000
		0x00, 0x00, 0x00, 0x64, // Assigned: 100
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseRouteTarget(rt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseRouteTarget_IPv4 benchmarks Route Target IPv4 Address Specific parsing
func BenchmarkParseRouteTarget_IPv4(b *testing.B) {
	// Sample Route Target (Type 0x0102 - IPv4 Address Specific)
	rt := []byte{
		0x01, 0x02,     // Type: IPv4 Address Specific
		10, 0, 0, 1,    // IPv4: 10.0.0.1
		0x00, 0x64,     // Assigned: 100
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseRouteTarget(rt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseRouteTarget_AS4 benchmarks Route Target 4-octet AS Specific parsing
func BenchmarkParseRouteTarget_AS4(b *testing.B) {
	// Sample Route Target (Type 0x0202 - 4-octet AS Specific)
	rt := []byte{
		0x02, 0x02,                 // Type: 4-octet AS Specific
		0x00, 0x01, 0x00, 0x00,     // AS: 65536
		0x00, 0xc8,                 // Assigned: 200
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseRouteTarget(rt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetLabelRange benchmarks label range calculation
func BenchmarkGetLabelRange(b *testing.B) {
	nlriBytes := []byte{
		0x00, 0x11,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x0a,
		0x18, 0x6a, 0x00,
	}

	route, _ := UnmarshalVPLSNLRI(nlriBytes)
	nlri := route.Route[0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = nlri.GetLabelRange()
	}
}
