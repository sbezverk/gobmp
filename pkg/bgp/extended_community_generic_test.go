package bgp

import (
	"encoding/binary"
	"math"
	"testing"
)

// TestGenericTransitiveSubTypes covers type 0x80 sub-types from the IANA
// "Generic Transitive Extended Community Sub-Types" registry:
// 0x0b E-Tree Info (RFC 7796 Section 6.2), 0x0c Flow spec
// traffic-rate-packets (RFC 8955 Section 7.2); 0x0d is not decoded.
func TestGenericTransitiveSubTypes(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{
			name:   "E-Tree Info, MBZ bits ignored, P and V set",
			input:  []byte{0x80, 0x0b, 0xf0, 0x64, 0x00, 0xc8, 0x00, 0x03},
			expect: "e-tree-info=RootVLAN=100 LeafVLAN=200 P=true V=true",
		},
		{
			name:   "E-Tree Info, V only",
			input:  []byte{0x80, 0x0b, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x01},
			expect: "e-tree-info=RootVLAN=10 LeafVLAN=20 P=false V=true",
		},
		{
			name:   "traffic-rate-packets 1000 pps",
			input:  []byte{0x80, 0x0c, 0xfd, 0xe8, 0x44, 0x7a, 0x00, 0x00},
			expect: "flowspec-traffic-rate-packets=AS: 65000 Rate: 1000 pps",
		},
		{
			name:   "traffic-rate-packets fractional rate is kept",
			input:  []byte{0x80, 0x0c, 0x00, 0x01, 0x3f, 0x00, 0x00, 0x00}, // 0.5
			expect: "flowspec-traffic-rate-packets=AS: 1 Rate: 0.5 pps",
		},
		{
			name:   "traffic-rate-packets large rate",
			input:  []byte{0x80, 0x0c, 0x00, 0x01, 0x4f, 0xb2, 0xd0, 0x5e}, // 6e9
			expect: "flowspec-traffic-rate-packets=AS: 1 Rate: 6000000000 pps",
		},
		{
			name:   "traffic-rate-packets 2^32 is exact",
			input:  []byte{0x80, 0x0c, 0x00, 0x01, 0x4f, 0x80, 0x00, 0x00},
			expect: "flowspec-traffic-rate-packets=AS: 1 Rate: 4294967296 pps",
		},
		{
			name:   "traffic-rate-packets float32(1e12) is exact",
			input:  []byte{0x80, 0x0c, 0x00, 0x01, 0x53, 0x68, 0xd4, 0xa5},
			expect: "flowspec-traffic-rate-packets=AS: 1 Rate: 999999995904 pps",
		},
		{
			name:   "traffic-rate-packets 0.1 uses float32 shortest decimal",
			input:  []byte{0x80, 0x0c, 0x00, 0x01, 0x3d, 0xcc, 0xcc, 0xcd},
			expect: "flowspec-traffic-rate-packets=AS: 1 Rate: 0.1 pps",
		},
		{
			name:   "traffic-rate-packets MaxFloat32 is exact",
			input:  []byte{0x80, 0x0c, 0x00, 0x01, 0x7f, 0x7f, 0xff, 0xff},
			expect: "flowspec-traffic-rate-packets=AS: 1 Rate: 340282346638528859811704183484516925440 pps",
		},
		{
			name:   "traffic-rate-packets negative is treated as zero",
			input:  []byte{0x80, 0x0c, 0x00, 0x00, 0xc4, 0x7a, 0x00, 0x00},
			expect: "flowspec-traffic-rate-packets=AS: 0 Rate: 0 pps",
		},
		{
			name:   "traffic-rate-packets NaN is not mapped to zero",
			input:  []byte{0x80, 0x0c, 0x00, 0x00, 0x7f, 0xc0, 0x00, 0x00},
			expect: "flowspec-traffic-rate-packets=AS: 0 Rate: NaN pps",
		},
		{
			name:   "traffic-rate-packets negative zero",
			input:  []byte{0x80, 0x0c, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00},
			expect: "flowspec-traffic-rate-packets=AS: 0 Rate: 0 pps",
		},
		{
			name:   "traffic-rate-packets +Inf",
			input:  []byte{0x80, 0x0c, 0x00, 0x00, 0x7f, 0x80, 0x00, 0x00},
			expect: "flowspec-traffic-rate-packets=AS: 0 Rate: +Inf pps",
		},
		{
			name:   "E-Tree Info, MBZ and reserved bits ignored",
			input:  []byte{0x80, 0x0b, 0xf0, 0x64, 0xf0, 0xc8, 0xff, 0xfc},
			expect: "e-tree-info=RootVLAN=100 LeafVLAN=200 P=false V=false",
		},
		{
			name:   "SFC classifier sub-type 0x0d is unknown",
			input:  []byte{0x80, 0x0d, 0x00, 0x01, 0x00, 0xff, 0x00, 0x02},
			expect: "Subtype unknown=[ 0x00, 0x01, 0x00, 0xFF, 0x00, 0x02 ]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := makeExtCommunity(tt.input)
			if err != nil {
				t.Fatalf("makeExtCommunity() error = %v", err)
			}
			if got := ext.String(); got != tt.expect {
				t.Errorf("got %s, want %s", got, tt.expect)
			}
		})
	}
}

// TestGenericTransitivePart2Part3SubTypes: the IANA "Generic Transitive
// Extended Community Part 2 Sub-Types" registry (type 0x81) assigns only
// 0x08, and "Part 3" (type 0x82) assigns 0x04, 0x08, 0x84 and 0x85; only
// 0x08 is flowspec (rt-redirect, RFC 8955 Section 7.4), so 0x06, 0x07 and
// 0x09 must not get flowspec names there.
func TestGenericTransitivePart2Part3SubTypes(t *testing.T) {
	tests := []struct {
		input  []byte
		expect string
	}{
		{[]byte{0x81, 0x08, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x64}, "flowspec-redirect=10.0.0.1:100"},
		{[]byte{0x82, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64}, "flowspec-redirect=65536:100"},
		{[]byte{0x81, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]"},
		{[]byte{0x81, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]"},
		{[]byte{0x81, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E ]"},
		{[]byte{0x82, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]"},
		{[]byte{0x82, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]"},
		{[]byte{0x82, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E ]"},
		{[]byte{0x82, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]"},
		{[]byte{0x82, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]"},
		{[]byte{0x82, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]"},
		{[]byte{0x82, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]"},
	}
	for _, tt := range tests {
		ext, err := makeExtCommunity(tt.input)
		if err != nil {
			t.Fatalf("makeExtCommunity(% x) error = %v", tt.input, err)
		}
		if got := ext.String(); got != tt.expect {
			t.Errorf("% x: got %s, want %s", tt.input, got, tt.expect)
		}
	}
}

// TestFlowspecTrafficRateBytes: RFC 8955 Section 7.1 says negative
// traffic-rate-bytes values MUST be treated as zero. The IEEE float is printed
// as bytes per second times 8 (bps) without integer truncation.
func TestFlowspecTrafficRateBytes(t *testing.T) {
	tests := []struct {
		name   string
		bits   uint32
		expect string
	}{
		{"1000 B/s", math.Float32bits(1000), "8000"},
		{"zero", 0, "0"},
		{"negative zero", 0x80000000, "0"},
		{"-1000", math.Float32bits(-1000), "0"},
		{"-1", math.Float32bits(-1), "0"},
		{"0.5 B/s", math.Float32bits(0.5), "4"},
		{"0.9 B/s", math.Float32bits(0.9), "7.2"},
		{"1.9 B/s", math.Float32bits(1.9), "15.2"},
		{"536870880 B/s", 0x4dffffff, "4294967040"},
		{"2^29 B/s", 0x4e000000, "4294967296"},
		{"1.25e9 B/s", 0x4e9502f9, "10000000000"},
		{"1e12 B/s", math.Float32bits(1e12), "7999999967232"},
		{"MaxFloat32 is finite", 0x7f7fffff, "2722258773108230878493633467876135403520"},
		{"NaN", 0x7fc00000, "NaN"},
		{"+Inf", 0x7f800000, "+Inf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := []byte{0x80, 0x06, 0x00, 0x07, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(v[4:], tt.bits)
			ext, err := makeExtCommunity(v)
			if err != nil {
				t.Fatal(err)
			}
			want := "flowspec-traffic-rate=AS: 7 Rate: " + tt.expect + " bps"
			if got := ext.String(); got != want {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}
}
