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
			got, err := UnmarshalRoutesAF(tt.input, tt.pathID, true)
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
	_, err := UnmarshalRoutesAF([]byte{0xFF}, false, true)
	if err == nil {
		t.Fatal("expected error for malformed input, got nil")
	}
}

// TestUnmarshalRoutes_RetrySucceeds verifies the retry path works when flipping pathID helps.
func TestUnmarshalRoutes_RetrySucceeds(t *testing.T) {
	// Valid route without pathID: length=8, prefix=10.0.0.0
	input := []byte{0x08, 0x0a}
	// Call with pathID=true — fails (need 4 bytes for PathID), retries with pathID=false → succeeds
	routes, err := UnmarshalRoutesAF(input, true, false)
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

func TestUnmarshalRoutesAF(t *testing.T) {
	v6 := func(bits byte) []byte { return append([]byte{bits}, make([]byte, (int(bits)+7)/8)...) }
	tests := []struct {
		name    string
		input   []byte
		pathID  bool
		ipv6    bool
		wantErr bool
	}{
		{"IPv4 /32", []byte{32, 10, 0, 0, 1}, false, false, false},
		// The flipped Path ID parse reads 0xff as a length, so it fails too
		{"IPv4 /33", []byte{33, 0xff, 0xff, 0xff, 0xff, 0x80}, false, false, true},
		{"IPv6 /128", v6(128), false, true, false},
		{"IPv6 /129", v6(129), false, true, true},
		{"IPv6 /129 with Path ID", append([]byte{0x81, 0, 0, 1}, v6(129)...), true, true, true},
		{"truncated", []byte{32, 10}, false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalRoutesAF(tt.input, tt.pathID, tt.ipv6)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// A too-long prefix is malformed, not a wrong Path ID guess: no retry, no routes.
// A wrong guess with valid lengths still retries.
func TestUnmarshalRoutesAF_BoundNoRetry(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		pathID    bool
		ipv6      bool
		wantErr   bool
		wantPaths []uint32
	}{
		{"IPv4 /33 with Path ID", []byte{0, 0, 0, 1, 0x21, 0x0a, 0x0b, 0x0c, 0, 0}, true, false, true, nil},
		{"IPv6 /129 with Path ID", append([]byte{0, 0, 0, 1, 0x81}, make([]byte, 17)...), true, true, true, nil},
		{"no Path ID flag, Path ID byte reads as /33", []byte{0x21, 0, 0, 1, 24, 10, 0, 0}, false, false, true, nil},
		{"retry: Path ID flag, none present", []byte{24, 10, 0, 0}, true, false, false, []uint32{0}},
		{"retry: no flag, Path ID present", []byte{0, 0, 0, 7, 32, 10, 0, 0, 1}, false, false, false, []uint32{7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes, err := UnmarshalRoutesAF(tt.input, tt.pathID, tt.ipv6)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(routes) != len(tt.wantPaths) {
				t.Fatalf("routes = %+v, want %d", routes, len(tt.wantPaths))
			}
			for i, r := range routes {
				if r.PathID != tt.wantPaths[i] {
					t.Errorf("route %d Path ID = %d, want %d", i, r.PathID, tt.wantPaths[i])
				}
			}
		})
	}
}

func TestGetPrefixIPReachabilityBound(t *testing.T) {
	tests := []struct {
		name    string
		value   []byte
		ipv4    bool
		wantNil bool
	}{
		{"IPv4 /32", []byte{32, 10, 0, 0, 1}, true, false},
		{"IPv4 /33", []byte{33, 0xff, 0xff, 0xff, 0xff, 0x80}, true, true},
		// Read with a Path ID this is 10.0.0.0/8; the TLV has none, so no retry.
		{"IPv4 /33 not retried", []byte{0x21, 0x0a, 0, 0, 8, 0x0a}, true, true},
		{"IPv6 /128", append([]byte{128}, make([]byte, 16)...), false, false},
		{"IPv6 /129", append([]byte{129}, make([]byte, 17)...), false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd := &PrefixDescriptor{PrefixTLV: map[uint16]TLV{265: {Type: 265, Value: tt.value}}}
			if got := pd.GetPrefixIPReachability(tt.ipv4); (got == nil) != tt.wantNil {
				t.Errorf("route = %+v, wantNil %v", got, tt.wantNil)
			}
		})
	}
}
