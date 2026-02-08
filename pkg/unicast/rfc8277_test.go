package unicast

import (
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// TestRFC8277_LabeledUnicastIPv4 validates IPv4 labeled unicast NLRI parsing per RFC 8277.
// Wire format per route: [PathID (4, optional)] + Length (1) + Label (3 per label) + Prefix (variable).
// Length field = total bits including label(s): label_bits + prefix_bits.
func TestRFC8277_LabeledUnicastIPv4(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		pathID bool
		want   *base.MPNLRI
	}{
		{
			name: "Single label /32 prefix 10.1.2.3",
			// Length=0x38(56)=24 label bits + 32 prefix bits
			input:  []byte{0x38, 0x00, 0x00, 0x31, 0x0a, 0x01, 0x02, 0x03},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x0a, 0x01, 0x02, 0x03},
					},
				},
			},
		},
		{
			name: "Single label /24 prefix 192.168.1.0",
			// Length=0x30(48)=24+24
			input:  []byte{0x30, 0x00, 0x00, 0x31, 0xc0, 0xa8, 0x01},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 24,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0xc0, 0xa8, 0x01},
					},
				},
			},
		},
		{
			name: "Single label /16 prefix 172.16.0.0",
			// Length=0x28(40)=24+16
			input:  []byte{0x28, 0x00, 0x00, 0x31, 0xac, 0x10},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 16,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0xac, 0x10},
					},
				},
			},
		},
		{
			name: "Single label /8 prefix 10.0.0.0",
			// Length=0x20(32)=24+8
			input:  []byte{0x20, 0x00, 0x00, 0x31, 0x0a},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 8,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x0a},
					},
				},
			},
		},
		{
			name: "Max 20-bit label value 1048575",
			// Label bytes: 0xFF, 0xFF, 0xF1 -> Value=(0xFFFFF0)>>4=1048575, Exp=(0x01&0x0E)>>1=0, BoS=1
			input:  []byte{0x38, 0xFF, 0xFF, 0xF1, 0x0a, 0x00, 0x00, 0x01},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{Value: 1048575, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x01},
					},
				},
			},
		},
		{
			name: "Label with non-zero EXP bits",
			// Label bytes: 0x00, 0x00, 0x37 -> Value=(0x000030)>>4=3, Exp=(0x07&0x0E)>>1=3, BoS=1
			input:  []byte{0x38, 0x00, 0x00, 0x37, 0x0a, 0x00, 0x00, 0x01},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{Value: 3, Exp: 3, BoS: true},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x01},
					},
				},
			},
		},
		{
			name: "Explicit null label (value 0)",
			// Label bytes: 0x00, 0x00, 0x01 -> Value=0, Exp=0, BoS=1
			input:  []byte{0x38, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x01},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{Value: 0, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x01},
					},
				},
			},
		},
		{
			name: "IPv4 /32 with PathID",
			input: []byte{
				0x00, 0x00, 0x00, 0x01, // PathID=1
				0x38,                   // Length=56=24+32
				0x00, 0x00, 0x31,       // Label: Value=3, BoS=true
				0x0a, 0x00, 0x00, 0x01, // Prefix: 10.0.0.1
			},
			pathID: true,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 32,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x01},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLUNLRI(tt.input, tt.pathID)
			if err != nil {
				t.Fatalf("UnmarshalLUNLRI() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalLUNLRI() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRFC8277_LabeledUnicastIPv6 validates IPv6 labeled unicast NLRI parsing per RFC 8277.
func TestRFC8277_LabeledUnicastIPv6(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		pathID bool
		want   *base.MPNLRI
	}{
		{
			name: "IPv6 /48 prefix 2001:db8:1::",
			// Length=0x48(72)=24 label + 48 prefix
			input: []byte{
				0x48,             // Length=72
				0x00, 0x00, 0x31, // Label: Value=3, BoS=true
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, // 2001:0db8:0001 (6 bytes)
			},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 48,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01},
					},
				},
			},
		},
		{
			name: "IPv6 /64 prefix 2001:db8:abcd:1234::",
			// Length=0x58(88)=24 label + 64 prefix
			input: []byte{
				0x58,             // Length=88
				0x00, 0x00, 0x31, // Label: Value=3, BoS=true
				0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12, 0x34, // 8 bytes
			},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 64,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12, 0x34},
					},
				},
			},
		},
		{
			name: "IPv6 /128 host route 2001:db8::1",
			// Length=0x98(152)=24 label + 128 prefix
			input: []byte{
				0x98,             // Length=152
				0x00, 0x00, 0x31, // Label: Value=3, BoS=true
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 16 bytes
			},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 128,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{
							0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
						},
					},
				},
			},
		},
		{
			name: "IPv6 loopback ::1/128",
			// Length=0x98(152)=24+128
			input: []byte{
				0x98,             // Length=152
				0x00, 0x00, 0x31, // Label
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 128,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
						},
					},
				},
			},
		},
		{
			name: "IPv6 /48 with PathID",
			input: []byte{
				0x00, 0x00, 0x00, 0x02, // PathID=2
				0x48,             // Length=72
				0x00, 0x00, 0x31, // Label
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,
			},
			pathID: true,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 2,
						Length: 48,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLUNLRI(tt.input, tt.pathID)
			if err != nil {
				t.Fatalf("UnmarshalLUNLRI() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalLUNLRI() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRFC8277_MultiLabelStack validates MPLS label stack parsing per RFC 8277 Section 2.
// Multiple labels use BoS=false for all except the last label.
func TestRFC8277_MultiLabelStack(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		pathID bool
		want   *base.MPNLRI
	}{
		{
			name: "Two label stack",
			// Length=0x50(80)=48 label bits (2*24) + 32 prefix bits
			// Label 1: 0x00,0x00,0x30 -> Value=3, Exp=0, BoS=false
			// Label 2: 0x00,0x00,0x41 -> Value=4, Exp=0, BoS=true
			input: []byte{
				0x50,             // Length=80
				0x00, 0x00, 0x30, // Label 1: Value=3, BoS=false
				0x00, 0x00, 0x41, // Label 2: Value=4, BoS=true
				0x0a, 0x00, 0x00, 0x01, // Prefix: 10.0.0.1/32
			},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: false},
							{Value: 4, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x01},
					},
				},
			},
		},
		{
			name: "Three label stack",
			// Length=0x68(104)=72 label bits (3*24) + 32 prefix bits
			// Label 1: Transport (100) -> 0x00,0x06,0x40 -> Value=100, BoS=false
			// Label 2: VPN (200) -> 0x00,0x0C,0x80 -> Value=200, BoS=false
			// Label 3: Service (300) -> 0x00,0x12,0xC1 -> Value=300, BoS=true
			input: []byte{
				0x68,             // Length=104
				0x00, 0x06, 0x40, // Label 1: Value=100, BoS=false
				0x00, 0x0C, 0x80, // Label 2: Value=200, BoS=false
				0x00, 0x12, 0xC1, // Label 3: Value=300, BoS=true
				0xC0, 0xA8, 0x01, 0x01, // Prefix: 192.168.1.1/32
			},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{Value: 100, Exp: 0, BoS: false},
							{Value: 200, Exp: 0, BoS: false},
							{Value: 300, Exp: 0, BoS: true},
						},
						Prefix: []byte{0xC0, 0xA8, 0x01, 0x01},
					},
				},
			},
		},
		{
			name: "Two labels with different EXP values",
			// Label 1: 0x00,0x00,0x34 -> Value=3, Exp=(0x04&0x0E)>>1=2, BoS=false
			// Label 2: 0x00,0x00,0x47 -> Value=4, Exp=(0x07&0x0E)>>1=3, BoS=true
			input: []byte{
				0x50,             // Length=80=48+32
				0x00, 0x00, 0x34, // Label 1: Value=3, Exp=2, BoS=false
				0x00, 0x00, 0x47, // Label 2: Value=4, Exp=3, BoS=true
				0xAC, 0x10, 0x00, 0x01, // Prefix: 172.16.0.1/32
			},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{Value: 3, Exp: 2, BoS: false},
							{Value: 4, Exp: 3, BoS: true},
						},
						Prefix: []byte{0xAC, 0x10, 0x00, 0x01},
					},
				},
			},
		},
		{
			name: "Two label stack with IPv6 prefix (6PE scenario)",
			// Length=0x70(112)=48 label bits + 64 prefix bits
			input: []byte{
				0x70,             // Length=112
				0x00, 0x00, 0x30, // Label 1: Value=3, BoS=false
				0x00, 0x00, 0x41, // Label 2: Value=4, BoS=true
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, // 2001:db8:1::/64
			},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 64,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: false},
							{Value: 4, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLUNLRI(tt.input, tt.pathID)
			if err != nil {
				t.Fatalf("UnmarshalLUNLRI() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalLUNLRI() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRFC8277_CompatibilityField validates the 0x800000 compatibility field handling
// per RFC 8277. Routes with this marker have Label=nil (used for labeled unicast withdrawals).
func TestRFC8277_CompatibilityField(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		pathID bool
		want   *base.MPNLRI
	}{
		{
			name: "Single withdrawal with compatibility field",
			// Length=0x30(48)=24 compat bits + 24 prefix bits
			input: []byte{
				0x00, 0x00, 0x00, 0x01, // PathID=1
				0x30,             // Length=48
				0x80, 0x00, 0x00, // Compatibility field
				0x0a, 0x00, 0x67, // Prefix 10.0.103
			},
			pathID: true,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 24,
						Label:  nil,
						Prefix: []byte{0x0a, 0x00, 0x67},
					},
				},
			},
		},
		{
			name: "Multiple withdrawals with PathID",
			input: []byte{
				0x00, 0x00, 0x00, 0x01, // PathID=1
				0x30,             // Length=48
				0x80, 0x00, 0x00, // Compatibility field
				0x0a, 0x00, 0x67, // Prefix: 10.0.103
				0x00, 0x00, 0x00, 0x01, // PathID=1
				0x30,             // Length=48
				0x80, 0x00, 0x00, // Compatibility field
				0x0a, 0x00, 0x66, // Prefix: 10.0.102
				0x00, 0x00, 0x00, 0x01, // PathID=1
				0x30,             // Length=48
				0x80, 0x00, 0x00, // Compatibility field
				0x0a, 0x00, 0x65, // Prefix: 10.0.101
			},
			pathID: true,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 24,
						Label:  nil,
						Prefix: []byte{0x0a, 0x00, 0x67},
					},
					{
						PathID: 1,
						Length: 24,
						Label:  nil,
						Prefix: []byte{0x0a, 0x00, 0x66},
					},
					{
						PathID: 1,
						Length: 24,
						Label:  nil,
						Prefix: []byte{0x0a, 0x00, 0x65},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLUNLRI(tt.input, tt.pathID)
			if err != nil {
				t.Fatalf("UnmarshalLUNLRI() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalLUNLRI() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRFC8277_MultipleRoutes validates parsing of multiple labeled routes in a single NLRI.
func TestRFC8277_MultipleRoutes(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		pathID bool
		want   *base.MPNLRI
	}{
		{
			name: "Three IPv4 routes without PathID",
			input: []byte{
				// Route 1: 10.0.0.0/24
				0x30,             // Length=48=24+24
				0x00, 0x00, 0x31, // Label: Value=3, BoS=true
				0x0a, 0x00, 0x00, // 10.0.0.0/24
				// Route 2: 172.16.0.0/16
				0x28,             // Length=40=24+16
				0x00, 0x00, 0x31, // Label: Value=3, BoS=true
				0xac, 0x10, // 172.16.0.0/16
				// Route 3: 192.168.1.0/24
				0x30,             // Length=48=24+24
				0x00, 0x00, 0x31, // Label: Value=3, BoS=true
				0xc0, 0xa8, 0x01, // 192.168.1.0/24
			},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 24,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x0a, 0x00, 0x00},
					},
					{
						Length: 16,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0xac, 0x10},
					},
					{
						Length: 24,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0xc0, 0xa8, 0x01},
					},
				},
			},
		},
		{
			name: "Two IPv4 routes with PathID (Add-Path)",
			input: []byte{
				// Route 1
				0x00, 0x00, 0x00, 0x01, // PathID=1
				0x38,                   // Length=56=24+32
				0x00, 0x00, 0x31,       // Label
				0x0a, 0x00, 0x00, 0x01, // 10.0.0.1/32
				// Route 2
				0x00, 0x00, 0x00, 0x02, // PathID=2
				0x38,                   // Length=56
				0x00, 0x00, 0x31,       // Label
				0x0a, 0x00, 0x00, 0x02, // 10.0.0.2/32
			},
			pathID: true,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 32,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x01},
					},
					{
						PathID: 2,
						Length: 32,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x02},
					},
				},
			},
		},
		{
			name: "Two IPv6 labeled routes",
			input: []byte{
				// Route 1: 2001:db8:1::/48
				0x48,             // Length=72=24+48
				0x00, 0x00, 0x31, // Label
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,
				// Route 2: 2001:db8:2::/48
				0x48,             // Length=72
				0x00, 0x00, 0x31, // Label
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02,
			},
			pathID: false,
			want: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 48,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01},
					},
					{
						Length: 48,
						Label: []*base.Label{
							{Value: 3, Exp: 0, BoS: true},
						},
						Prefix: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLUNLRI(tt.input, tt.pathID)
			if err != nil {
				t.Fatalf("UnmarshalLUNLRI() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalLUNLRI() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRFC8277_ErrorCases validates error handling for malformed labeled unicast NLRI.
func TestRFC8277_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		pathID  bool
		wantErr bool
		want    *base.MPNLRI
	}{
		{
			name:    "Empty input returns empty NLRI",
			input:   []byte{},
			pathID:  false,
			wantErr: false,
			want:    &base.MPNLRI{NLRI: []base.Route{}},
		},
		{
			name:    "Truncated PathID - only 3 bytes",
			input:   []byte{0x00, 0x00, 0x01},
			pathID:  true,
			wantErr: true,
		},
		{
			name:    "Zero length byte triggers error",
			input:   []byte{0x00, 0x00, 0x00, 0x01, 0x00},
			pathID:  true,
			wantErr: true,
		},
		{
			name: "Truncated label - only 2 label bytes",
			input: []byte{
				0x38,       // Length=56 (expects 3 label bytes + 4 prefix bytes)
				0x00, 0x00, // Only 2 bytes of label
			},
			pathID:  false,
			wantErr: true,
		},
		{
			name: "Truncated prefix - label complete but prefix too short",
			input: []byte{
				0x38,             // Length=56 (expects 4 prefix bytes)
				0x00, 0x00, 0x31, // Label complete
				0x0a, 0x00, // Only 2 prefix bytes (need 4)
			},
			pathID:  false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLUNLRI(tt.input, tt.pathID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("UnmarshalLUNLRI() expected error, got nil (result: %+v)", got)
				}
			} else {
				if err != nil {
					t.Fatalf("UnmarshalLUNLRI() unexpected error: %v", err)
				}
				if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
					t.Errorf("UnmarshalLUNLRI() = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}
