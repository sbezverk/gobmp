package flowspec

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalFlowspecNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *NLRI
		fail   bool
	}{
		{
			name:  "Type 2 (Source Prefix)",
			input: []byte{0x05, 0x02, 0x18, 0x0A, 0x00, 0x07},
			expect: &NLRI{
				Length: 5,
				Spec: []Spec{
					&PrefixSpec{
						SpecType:     2,
						PrefixLength: 24,
						Prefix:       []byte{0x0A, 0x00, 0x07},
					},
				},
				SpecHash: "e3476bd744569c33da483e7edadf18dd",
			},
			fail: false,
		},
		{
			name:  "Type 3 (IP Protocol)",
			input: []byte{0x03, 0x03, 0x81, 0x2F},
			expect: &NLRI{
				Length: 3,
				Spec: []Spec{
					&GenericSpec{
						SpecType: 3,
						OpVal: []*OpVal{
							{
								Op: &Operator{
									EOLBit: true,
									Length: 1,
									EQBit:  true,
								},
								Val: []byte{0x2f},
							},
						},
					},
				},
				SpecHash: "59deb4eb292d1247522f4a6201479f0e",
			},
			fail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalFlowspecNLRI(tt.input)
			if err != nil && !tt.fail {
				t.Fatalf("failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Logf("Diffs: %+v", deep.Equal(tt.expect, got))
				t.Fatalf("expected NLRI %+v does not match marshaled NLRI: %+v", tt.expect, got)
			}
		})
	}
}

// TestIPv6PrefixSpec_ErrorPaths validates the two error branches in makeIPv6PrefixSpec.
func TestIPv6PrefixSpec_ErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{
			// offset(32) > prefix_len(16): bits = 16-32 = -16
			name:    "offset exceeds prefix length",
			input:   []byte{0x03, 0x01, 0x10, 0x20},
			wantErr: "exceeds prefix length",
		},
		{
			// prefix_len=64, offset=0: need 8 bytes of prefix, only 2 provided
			name:    "not enough bytes for prefix",
			input:   []byte{0x05, 0x01, 0x40, 0x00, 0xAA, 0xBB},
			wantErr: "not enough bytes for IPv6 prefix",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalAllIPv6FlowspecNLRI(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestUnmarshalFlowspecNLRI_ZeroLength(t *testing.T) {
	// A single 0x00 byte sets fs.Length = 0, triggering the
	// "invalid zero-length Flowspec NLRI" guard.
	input := []byte{0x00}
	got, err := UnmarshalFlowspecNLRI(input)
	if err == nil {
		t.Fatal("expected error for zero-length FlowSpec NLRI, got nil")
	}
	if got != nil {
		t.Fatalf("expected nil NLRI, got %+v", got)
	}
	if !strings.Contains(err.Error(), "zero-length Flowspec NLRI") {
		t.Fatalf("unexpected error message: got %q, want substring %q", err.Error(), "zero-length Flowspec NLRI")
	}
}
