package multicast

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalMulticastNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *base.MPNLRI
		pathID bool
	}{
		{
			name:  "mp multicast nlri 1",
			input: []byte{0x18, 0x0a, 0x00, 0x82},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 0x18,
						Prefix: []byte{0x0a, 0x00, 0x82},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "mp multicast nlri 2",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x20, 0x0a, 0x00, 0x00, 0x02},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 0x20,
						Prefix: []byte{0x0a, 0x00, 0x00, 0x02},
					},
				},
			},
			pathID: true,
		},
		{
			name:  "mp multicast nlri 3",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x16, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x18, 0xe0, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x18, 0xe0, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x18, 0xe0, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x18, 0xe0, 0x00, 0x01},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 0x16,
						Prefix: []byte{0xe0, 0x00, 0x08},
					},
					{
						PathID: 1,
						Length: 0x18,
						Prefix: []byte{0xe0, 0x00, 0x04},
					},
					{
						PathID: 1,
						Length: 0x18,
						Prefix: []byte{0xe0, 0x00, 0x03},
					},
					{
						PathID: 1,
						Length: 0x18,
						Prefix: []byte{0xe0, 0x00, 0x02},
					},
					{
						PathID: 1,
						Length: 0x18,
						Prefix: []byte{0xe0, 0x00, 0x01},
					},
				},
			},
			pathID: true,
		},
		{
			name:  "Default multicast route",
			input: []byte{0x04, 0xe0},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 0x04,
						Prefix: []byte{0xe0},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "IPv4 multicast prefix 224.0.0.0/4",
			input: []byte{0x04, 0xe0},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 4,
						Prefix: []byte{0xe0},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "IPv4 multicast prefix 239.255.255.255/32",
			input: []byte{0x20, 0xef, 0xff, 0xff, 0xff},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Prefix: []byte{0xef, 0xff, 0xff, 0xff},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "Multiple multicast prefixes",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x18, 0xe0, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x18, 0xe0, 0x02, 0x02},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 24,
						Prefix: []byte{0xe0, 0x01, 0x01},
					},
					{
						PathID: 1,
						Length: 24,
						Prefix: []byte{0xe0, 0x02, 0x02},
					},
				},
			},
			pathID: true,
		},
		{
			name:  "IPv6 multicast prefix ff00::/8",
			input: []byte{0x08, 0xff},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 8,
						Prefix: []byte{0xff},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "IPv6 multicast prefix ff02::1/128",
			input: []byte{0x80, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 128,
						Prefix: []byte{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "Default route 0.0.0.0/0",
			input: []byte{0x00},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 0,
						Prefix: []byte{},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "IPv4 multicast /8 prefix",
			input: []byte{0x08, 0xe1},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 8,
						Prefix: []byte{0xe1},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "IPv4 multicast /16 prefix 232.0.0.0/16",
			input: []byte{0x10, 0xe8, 0x00},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 16,
						Prefix: []byte{0xe8, 0x00},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "IPv6 multicast ff02::2/128 with PathID",
			input: []byte{0x00, 0x00, 0x00, 0x05, 0x80, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 5,
						Length: 128,
						Prefix: []byte{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
					},
				},
			},
			pathID: true,
		},
		{
			name:  "Mixed length prefixes with PathID",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x08, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x10, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x01, 0x18, 0xe2, 0x00, 0x00},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 8,
						Prefix: []byte{0xe0},
					},
					{
						PathID: 1,
						Length: 16,
						Prefix: []byte{0xe1, 0x00},
					},
					{
						PathID: 1,
						Length: 24,
						Prefix: []byte{0xe2, 0x00, 0x00},
					},
				},
			},
			pathID: true,
		},
		{
			name:  "IPv6 multicast /64 prefix",
			input: []byte{0x40, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 64,
						Prefix: []byte{0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "SSM range 232.0.0.0/8",
			input: []byte{0x08, 0xe8},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 8,
						Prefix: []byte{0xe8},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "GLOP addressing 233.0.0.0/8",
			input: []byte{0x08, 0xe9},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 8,
						Prefix: []byte{0xe9},
					},
				},
			},
			pathID: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalMulticastNLRI(tt.input, tt.pathID)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Logf("Differences: %+v", deep.Equal(tt.expect, got))
				t.Fatal("test failed as expected nlri does not match actual nlri")
			}
		})
	}
}

func TestUnmarshalMulticastNLRIErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		pathID  bool
		wantErr bool
	}{
		{
			name:    "Empty input",
			input:   []byte{},
			pathID:  false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalMulticastNLRI(tt.input, tt.pathID)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalMulticastNLRI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("UnmarshalMulticastNLRI() returned nil without error")
			}
		})
	}
}
