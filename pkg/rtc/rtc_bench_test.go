package rtc

import "testing"

// Benchmark NLRI unmarshaling for different RTC types

func BenchmarkUnmarshalRTCNLRI_Wildcard(b *testing.B) {
	data := []byte{0x00} // Wildcard (0 bits)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = UnmarshalRTCNLRI(data)
	}
}

func BenchmarkUnmarshalRTCNLRI_OriginASOnly(b *testing.B) {
	data := []byte{
		0x20,                   // Length: 32 bits
		0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = UnmarshalRTCNLRI(data)
	}
}

func BenchmarkUnmarshalRTCNLRI_FullType0(b *testing.B) {
	data := []byte{
		0x60,                   // Length: 96 bits
		0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
		0x00, 0x02, // Type: 0x00 (2-byte AS), SubType: 0x02
		0x00, 0x64, // AS: 100
		0x00, 0x00, 0x00, 0x01, // Value: 1
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = UnmarshalRTCNLRI(data)
	}
}

func BenchmarkUnmarshalRTCNLRI_FullType1(b *testing.B) {
	data := []byte{
		0x60,                   // Length: 96 bits
		0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
		0x01, 0x02, // Type: 0x01 (IPv4), SubType: 0x02
		10, 0, 0, 1, // IPv4: 10.0.0.1
		0x00, 0x64, // Value: 100
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = UnmarshalRTCNLRI(data)
	}
}

func BenchmarkUnmarshalRTCNLRI_FullType2(b *testing.B) {
	data := []byte{
		0x60,                   // Length: 96 bits
		0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
		0x02, 0x02, // Type: 0x02 (4-byte AS), SubType: 0x02
		0x00, 0x01, 0x00, 0x00, // AS: 65536
		0x00, 0x0A, // Value: 10
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = UnmarshalRTCNLRI(data)
	}
}

func BenchmarkUnmarshalRTCNLRI_MultipleNLRIs(b *testing.B) {
	data := []byte{
		// Wildcard
		0x00,
		// AS only
		0x20,
		0x00, 0x00, 0x00, 0x64,
		// Full Type 0
		0x60,
		0x00, 0x00, 0xFD, 0xE8,
		0x00, 0x02,
		0x00, 0xC8,
		0x00, 0x00, 0x00, 0x05,
		// Full Type 1
		0x60,
		0x00, 0x00, 0xFD, 0xE8,
		0x01, 0x02,
		10, 0, 0, 1,
		0x00, 0x64,
		// Full Type 2
		0x60,
		0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x02,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x0A,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = UnmarshalRTCNLRI(data)
	}
}

func BenchmarkNLRIString_Wildcard(b *testing.B) {
	nlri := &NLRI{Length: 0}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = nlri.String()
	}
}

func BenchmarkNLRIString_OriginASOnly(b *testing.B) {
	nlri := &NLRI{Length: 32, OriginAS: 65000}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = nlri.String()
	}
}

func BenchmarkNLRIString_FullType0(b *testing.B) {
	nlri := &NLRI{
		Length:      96,
		OriginAS:    65000,
		RouteTarget: []byte{0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = nlri.String()
	}
}

func BenchmarkNLRIString_FullType1(b *testing.B) {
	nlri := &NLRI{
		Length:      96,
		OriginAS:    65000,
		RouteTarget: []byte{0x01, 0x02, 10, 0, 0, 1, 0x00, 0x64},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = nlri.String()
	}
}

func BenchmarkNLRIString_FullType2(b *testing.B) {
	nlri := &NLRI{
		Length:      96,
		OriginAS:    65000,
		RouteTarget: []byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = nlri.String()
	}
}
