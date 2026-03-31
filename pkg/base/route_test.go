package base

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestGetPrefixIPReachability(t *testing.T) {
	tests := []struct {
		name   string
		input  *PrefixDescriptor
		expect string

		ipv4 bool
	}{
		{
			name: "ipv4",
			input: &PrefixDescriptor{
				PrefixTLV: map[uint16]TLV{
					265: {
						Type:   265,
						Length: 5,
						Value:  []byte{32, 192, 168, 8, 8},
					},
				},
			},
			expect: "192.168.8.8",
			ipv4:   true,
		},
		{
			name: "ipv6",
			input: &PrefixDescriptor{
				PrefixTLV: map[uint16]TLV{
					265: {
						Type:   265,
						Length: 16,
						Value:  []byte{120, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					},
				},
			},
			expect: "10::",
			ipv4:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := tt.input.GetPrefixIPReachability(tt.ipv4)
			var rs string
			if route == nil {
				t.Errorf("failed, no routes returned")
				return
			}
			if len(route.Prefix) == 16 {
				rs = net.IP(route.Prefix).To16().String()
			} else {
				rs = net.IP(route.Prefix).To4().String()
			}
			if strings.Compare(tt.expect, rs) != 0 {
				t.Errorf("failed, expected %s route got %s route", tt.expect, rs)
			}
		})
	}
}

func TestUnmarshalBaseNLRI(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		expect  []Route
		pathID  bool
		wantErr bool
	}{
		{
			name:    "EoR Case",
			input:   []byte{},
			pathID:  false,
			expect:  []Route{},
			wantErr: false,
		},
		{
			name:   "Default prefix",
			input:  []byte{0x0},
			pathID: false,
			expect: []Route{
				{
					Length: 0x0,
					Prefix: []byte{},
				},
			},
		},
		{
			name:   "fail",
			input:  []byte{0, 8, 10, 24, 10, 0, 0, 24, 20, 0, 0},
			pathID: false,
			expect: []Route{
				{
					Length: 0x0,
					Prefix: []byte{},
				},
				{
					Length: 0x08,
					Prefix: []byte{10},
				},
				{
					Length: 24,
					Prefix: []byte{10, 0, 0},
				},
				{
					Length: 24,
					Prefix: []byte{20, 0, 0},
				},
			},
		},
		{
			name:   "Panic_1",
			input:  []byte{0x00, 0x00, 0x00, 0x01, 0x18, 0x43, 0xd3, 0x35, 0x00, 0x00, 0x00, 0x01, 0x18, 0x2d, 0xa0, 0x00},
			pathID: true,
			expect: []Route{
				{
					PathID: 1,
					Length: 24,
					Prefix: []byte{67, 211, 53},
				},
				{
					PathID: 1,
					Length: 24,
					Prefix: []byte{45, 160, 0},
				},
			},
		},
		{
			name:   "issue #227",
			input:  []byte{0x1C, 0x02, 0x02, 0x02, 0x00},
			pathID: false,
			expect: []Route{
				{
					PathID: 0,
					Length: 28,
					Prefix: []byte{2, 2, 2, 0},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalRoutes(tt.input, tt.pathID)
			if err != nil && !tt.wantErr {
				t.Fatalf("test failed with error: %+v", err)
			}
			if err == nil && tt.wantErr {
				t.Fatalf("test failed as expected error did not occur")
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}
		})
	}
}

// TestUnmarshalRoutes_RetryLimit verifies that malformed input fails after one retry
// instead of recursing infinitely.
func TestUnmarshalRoutes_RetryLimit(t *testing.T) {
	// Single byte 0xFF — invalid prefix length whether pathID=true or false.
	// With pathID=true: not enough bytes for PathID (need 4).
	// With pathID=false: prefix length 255, need 32 bytes but only 0 remain.
	// Both fail → should return error, not hang.
	_, err := UnmarshalRoutes([]byte{0xFF}, false)
	if err == nil {
		t.Fatal("expected error for malformed input, got nil")
	}
}

// TestUnmarshalRoutes_RetrySucceeds verifies the retry path works when flipping pathID helps.
func TestUnmarshalRoutes_RetrySucceeds(t *testing.T) {
	// Valid route without pathID: length=8, prefix=10.0.0.0
	input := []byte{0x08, 0x0a}
	// Call with pathID=true — fails (need 4 bytes for PathID), retries with pathID=false → succeeds
	routes, err := UnmarshalRoutes(input, true)
	if err != nil {
		t.Fatalf("expected retry to succeed, got error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Length != 8 {
		t.Errorf("expected prefix length 8, got %d", routes[0].Length)
	}
	if len(routes[0].Prefix) == 0 || routes[0].Prefix[0] != 0x0a {
		t.Errorf("expected prefix starting with 10 (0x0a), got %v", routes[0].Prefix)
	}
}
