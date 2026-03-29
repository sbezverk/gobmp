package unicast

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalUnicastNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *base.MPNLRI
		pathID bool
	}{
		{
			name:  "mp unicast nlri 1",
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
			name:  "mp unicast nlri 2",
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
			name:  "mp unicast nlri 3",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x16, 0x47, 0x47, 0x08, 0x00, 0x00, 0x00, 0x01, 0x18, 0x47, 0x47, 0x04, 0x00, 0x00, 0x00, 0x01, 0x18, 0x47, 0x47, 0x03, 0x00, 0x00, 0x00, 0x01, 0x18, 0x47, 0x47, 0x02, 0x00, 0x00, 0x00, 0x01, 0x18, 0x47, 0x47, 0x01},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 0x16,
						Prefix: []byte{0x47, 0x47, 0x08},
					},
					{
						PathID: 1,
						Length: 0x18,
						Prefix: []byte{0x47, 0x47, 0x04},
					},
					{
						PathID: 1,
						Length: 0x18,
						Prefix: []byte{0x47, 0x47, 0x03},
					},
					{
						PathID: 1,
						Length: 0x18,
						Prefix: []byte{0x47, 0x47, 0x02},
					},
					{
						PathID: 1,
						Length: 0x18,
						Prefix: []byte{0x47, 0x47, 0x01},
					},
				},
			},
			pathID: true,
		},
		{
			name:  "Default prefix",
			input: []byte{0x0},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 0x0,
						Prefix: []byte{},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "Panic case #1",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x17, 0x89, 0xe8, 0x70},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 23,
						Prefix: []byte{137, 232, 112},
					},
				},
			},
			pathID: true,
		},
		{
			name:  "Panic case #2",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x17, 0xd8, 0xee, 0xfe, 0x00, 0x00, 0x00, 0x01, 0x18, 0xcd, 0x6b, 0x58, 0x00, 0x00, 0x00, 0x01, 0x14, 0xcd, 0x63, 0x40, 0x00, 0x00, 0x00, 0x01, 0x18, 0xb1, 0xc8, 0xef, 0x00, 0x00, 0x00, 0x01, 0x18, 0xb1, 0xc8, 0xee},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 23,
						Prefix: []byte{216, 238, 254},
					},
					{
						PathID: 1,
						Length: 24,
						Prefix: []byte{205, 107, 88},
					},
					{
						PathID: 1,
						Length: 20,
						Prefix: []byte{205, 99, 64},
					},
					{
						PathID: 1,
						Length: 24,
						Prefix: []byte{177, 200, 239},
					},
					{
						PathID: 1,
						Length: 24,
						Prefix: []byte{177, 200, 238},
					},
				},
			},
			pathID: true,
		},
		{
			name:  "Panic case #3",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x80, 0x01, 0x92, 0x01, 0x68, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 128,
						Prefix: []byte{0x01, 0x92, 0x01, 0x68, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93},
					},
				},
			},
			pathID: true,
		},
		{
			name:  "issue_173",
			input: []byte{0x10, 0x20, 0x01},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 16,
						Prefix: []byte{0x20, 0x01},
					},
				},
			},
			pathID: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalUnicastNLRI(tt.input, tt.pathID)
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

func TestUnmarshalLUNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *base.MPNLRI
		pathID bool
	}{
		{
			name:  "mp unicast nlri 1",
			input: []byte{0x38, 0x00, 0x00, 0x31, 0x0a, 0x00, 0x00, 0x00},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{
								Value: 3,
								Exp:   0x0,
								BoS:   true,
							},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x00},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "mp unicast nlri 2",
			input: []byte{0x38, 0x00, 0x00, 0x31, 0x0a, 0x00, 0x00, 0x00},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						Length: 32,
						Label: []*base.Label{
							{
								Value: 3,
								Exp:   0x0,
								BoS:   true,
							},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x00},
					},
				},
			},
			pathID: false,
		},
		{
			name:  "mp unicast nlri 3",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x30, 0x00, 0x00, 0x31, 0xc0, 0xa8, 0x50, 0x00, 0x00, 0x00, 0x01, 0x38, 0x00, 0x00, 0x31, 0x5a, 0x1e, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x01, 0x30, 0x00, 0x00, 0x31, 0x09, 0x00, 0xcb, 0x00, 0x00, 0x00, 0x01, 0x30, 0x00, 0x00, 0x31, 0x09, 0x00, 0x67, 0x00, 0x00, 0x00, 0x01, 0x30, 0x00, 0x00, 0x31, 0x09, 0x00, 0x22},
			expect: &base.MPNLRI{
				NLRI: []base.Route{
					{
						PathID: 1,
						Length: 24,
						Label: []*base.Label{
							{
								Value: 3,
								Exp:   0x0,
								BoS:   true,
							},
						},
						Prefix: []byte{0xc0, 0xa8, 0x50},
					},
					{
						PathID: 1,
						Length: 32,
						Label: []*base.Label{
							{
								Value: 3,
								Exp:   0x0,
								BoS:   true,
							},
						},
						Prefix: []byte{90, 30, 10, 1},
					},
					{
						PathID: 1,
						Length: 24,
						Label: []*base.Label{
							{
								Value: 3,
								Exp:   0x0,
								BoS:   true,
							},
						},
						Prefix: []byte{9, 0, 203},
					},
					{
						PathID: 1,
						Length: 24,
						Label: []*base.Label{
							{
								Value: 3,
								Exp:   0x0,
								BoS:   true,
							},
						},
						Prefix: []byte{9, 0, 103},
					},
					{
						PathID: 1,
						Length: 24,
						Label: []*base.Label{
							{
								Value: 3,
								Exp:   0x0,
								BoS:   true,
							},
						},
						Prefix: []byte{9, 0, 34},
					},
				},
			},
			pathID: true,
		},
		{
			name:  "panic case#1",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x30, 0x80, 0x00, 0x00, 0x0a, 0x00, 0x67, 0x00, 0x00, 0x00, 0x01, 0x30, 0x80, 0x00, 0x00, 0x0a, 0x00, 0x66, 0x00, 0x00, 0x00, 0x01, 0x30, 0x80, 0x00, 0x00, 0x0a, 0x00, 0x65},
			expect: &base.MPNLRI{
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
			pathID: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLUNLRI(tt.input, tt.pathID)
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

// TestUnmarshalLUNLRI_NegativePrefixLength validates that malformed input with
// negative prefix length (total length < label bits) recovers via pathID retry.
// With pathID=true the first 4 bytes are consumed as PathID, leaving Length=0x0A(10)
// and prefixBitLen = 10-24 = -14. The error_handle retry with pathID=false parses
// the full slice as Length=0x38(56), one label, and a 32-bit prefix 10.0.0.7.
func TestUnmarshalLUNLRI_NegativePrefixLength(t *testing.T) {
	input := []byte{0x38, 0x00, 0x00, 0x31, 0x0A, 0x00, 0x00, 0x07}
	result, err := UnmarshalLUNLRI(input, true)
	if err != nil {
		t.Fatalf("expected pathID retry to succeed, got error: %v", err)
	}
	if len(result.NLRI) != 1 {
		t.Fatalf("expected 1 NLRI after retry, got %d", len(result.NLRI))
	}
	route := result.NLRI[0]
	if route.Length != 32 {
		t.Errorf("expected prefix length 32, got %d", route.Length)
	}
	if len(route.Prefix) != 4 || route.Prefix[0] != 0x0A || route.Prefix[3] != 0x07 {
		t.Errorf("expected prefix 10.0.0.7, got %v", route.Prefix)
	}
	if len(route.Label) != 1 || !route.Label[0].BoS {
		t.Errorf("expected 1 label with BoS=true, got %v", route.Label)
	}
}

// TestUnmarshalLUNLRI_PrefixLengthExceeds128 validates error for prefix length > 128 bits.
func TestUnmarshalLUNLRI_PrefixLengthExceeds128(t *testing.T) {
	// Length=0xFF(255 bits), Label(3)=0x000031 (BoS), prefix bits = 255-24 = 231 > 128
	input := []byte{
		0xFF,             // Length: 255 bits total
		0x00, 0x00, 0x31, // Label: value=3, BoS=true
	}
	// Pad with enough bytes for the parser to attempt reading
	padding := make([]byte, 32)
	input = append(input, padding...)
	_, err := UnmarshalLUNLRI(input, false)
	if err == nil {
		t.Fatal("expected error for prefix length exceeding 128 bits, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum 128") {
		t.Errorf("expected error about exceeding 128 bits, got: %v", err)
	}
}
