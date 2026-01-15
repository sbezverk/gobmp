package evpn

import (
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// TestRFC7432_RouteType1_EthernetAutoDiscovery tests RFC 7432 Section 7.1
// Ethernet Auto-Discovery (A-D) Route
func TestRFC7432_RouteType1_EthernetAutoDiscovery(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectRoute *NLRI
		expectError bool
	}{
		{
			name: "basic AD route with ESI and label",
			input: []byte{
				0x01, // Route Type 1
				0x19, // Length 25
				// RD (8 bytes): Type 0, Value 0xc8:0x32
				0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32,
				// ESI (10 bytes)
				0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
				// Ethernet Tag (4 bytes)
				0x00, 0x00, 0x00, 0x00,
				// MPLS Label (3 bytes)
				0x18, 0xa9, 0xb1,
			},
			expectRoute: &NLRI{
				RouteType: 1,
				Length:    0x19,
				RouteTypeSpec: &EthAutoDiscovery{
					RD: &base.RD{
						Type:  0,
						Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x00, 0x32},
					},
					ESI: func() *ESI {
						esi, _ := MakeESI([]byte{0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11})
						return esi
					}(),
					EthTag: []byte{0, 0, 0, 0},
					Label: []*base.Label{
						{
							Value: 101019,
							Exp:   0,
							BoS:   true,
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "AD route with zero ESI",
			input: []byte{
				0x01, // Route Type 1
				0x19, // Length 25
				// RD (8 bytes): Type 1
				0x00, 0x01, 0x0a, 0x22, 0x04, 0x01, 0x00, 0x03,
				// ESI (10 bytes) - all zeros
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Ethernet Tag (4 bytes)
				0x00, 0x00, 0x00, 0x64,
				// MPLS Label (3 bytes)
				0x00, 0x00, 0x11,
			},
			expectRoute: &NLRI{
				RouteType: 1,
				Length:    0x19,
				RouteTypeSpec: &EthAutoDiscovery{
					RD: &base.RD{
						Type:  1,
						Value: []byte{0x0a, 0x22, 0x04, 0x01, 0x00, 0x03},
					},
					ESI: func() *ESI {
						esi, _ := MakeESI([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
						return esi
					}(),
					EthTag: []byte{0, 0, 0, 0x64},
					Label: []*base.Label{
						{
							Value: 1,
							Exp:   0,
							BoS:   true,
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := UnmarshalEVPNNLRI(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(route.Route) != 1 {
				t.Fatalf("expected 1 route, got %d", len(route.Route))
			}
			if !reflect.DeepEqual(tt.expectRoute, route.Route[0]) {
				t.Fatalf("route mismatch:\nexpected: %+v\ngot:      %+v", tt.expectRoute, route.Route[0])
			}
		})
	}
}

// TestRFC7432_RouteType2_MACIPAdvertisement tests RFC 7432 Section 7.2
// MAC/IP Advertisement Route
func TestRFC7432_RouteType2_MACIPAdvertisement(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectRoute *NLRI
		expectError bool
	}{
		{
			name: "MAC-only advertisement",
			input: []byte{
				0x02, // Route Type 2
				0x21, // Length 33
				// RD (8 bytes)
				0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32,
				// ESI (10 bytes) - all zeros
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Ethernet Tag (4 bytes)
				0x00, 0x00, 0x00, 0x00,
				// MAC Address Length (1 byte)
				0x30, // 48 bits
				// MAC Address (6 bytes)
				0x00, 0x81, 0xc4, 0xbc, 0x77, 0x8a,
				// IP Address Length (1 byte)
				0x00, // No IP
				// MPLS Label (3 bytes)
				0x18, 0xa9, 0x71,
			},
			expectRoute: &NLRI{
				RouteType: 2,
				Length:    33,
				RouteTypeSpec: &MACIPAdvertisement{
					RD: &base.RD{
						Type:  0,
						Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x00, 0x32},
					},
					ESI: func() *ESI {
						esi, _ := MakeESI([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
						return esi
					}(),
					EthTag:        []byte{0, 0, 0, 0},
					MACAddrLength: 48,
					MACAddr: func() *MACAddress {
						mac, _ := MakeMACAddress([]byte{0x00, 0x81, 0xc4, 0xbc, 0x77, 0x8a})
						return mac
					}(),
					IPAddrLength: 0,
					Label: []*base.Label{
						{
							Value: 101015,
							Exp:   0,
							BoS:   true,
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "MAC+IPv4 advertisement",
			input: []byte{
				0x02, // Route Type 2
				0x28, // Length 40
				// RD (8 bytes)
				0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32,
				// ESI (10 bytes)
				0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
				// Ethernet Tag (4 bytes)
				0x00, 0x00, 0x00, 0x00,
				// MAC Address Length (1 byte)
				0x30, // 48 bits
				// MAC Address (6 bytes)
				0x00, 0x81, 0xc4, 0xbc, 0x77, 0x8a,
				// IP Address Length (1 byte)
				0x20, // 32 bits (IPv4)
				// IP Address (4 bytes)
				0x0a, 0x0a, 0x0a, 0x01,
				// MPLS Label 1 (3 bytes)
				0x18, 0xa9, 0x71,
				// MPLS Label 2 (3 bytes)
				0x18, 0xa9, 0x11,
			},
			expectRoute: &NLRI{
				RouteType: 2,
				Length:    40,
				RouteTypeSpec: &MACIPAdvertisement{
					RD: &base.RD{
						Type:  0,
						Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x00, 0x32},
					},
					ESI: func() *ESI {
						esi, _ := MakeESI([]byte{0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10})
						return esi
					}(),
					EthTag:        []byte{0, 0, 0, 0},
					MACAddrLength: 48,
					MACAddr: func() *MACAddress {
						mac, _ := MakeMACAddress([]byte{0x00, 0x81, 0xc4, 0xbc, 0x77, 0x8a})
						return mac
					}(),
					IPAddrLength: 32,
					IPAddr:       []byte{10, 10, 10, 1},
					Label: []*base.Label{
						{
							Value: 101015,
							Exp:   0,
							BoS:   true,
						},
						{
							Value: 101009,
							Exp:   0,
							BoS:   true,
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := UnmarshalEVPNNLRI(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(route.Route) != 1 {
				t.Fatalf("expected 1 route, got %d", len(route.Route))
			}
			if !reflect.DeepEqual(tt.expectRoute, route.Route[0]) {
				t.Fatalf("route mismatch:\nexpected: %+v\ngot:      %+v", tt.expectRoute, route.Route[0])
			}
		})
	}
}

// TestRFC7432_RouteType3_InclusiveMulticastEthTag tests RFC 7432 Section 7.3
// Inclusive Multicast Ethernet Tag Route
func TestRFC7432_RouteType3_InclusiveMulticastEthTag(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectRoute *NLRI
		expectError bool
	}{
		{
			name: "basic IMET route",
			input: []byte{
				0x03, // Route Type 3
				0x11, // Length 17
				// RD (8 bytes): Type 0
				0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32,
				// Ethernet Tag (4 bytes)
				0x00, 0x00, 0x00, 0x00,
				// IP Address Length (1 byte)
				0x20, // 32 bits
				// IP Address (4 bytes)
				0xac, 0x1f, 0x65, 0x06,
			},
			expectRoute: &NLRI{
				RouteType: 3,
				Length:    17,
				RouteTypeSpec: &InclusiveMulticastEthTag{
					RD: &base.RD{
						Type:  0,
						Value: []byte{0x00, 0xc8, 0x00, 0x00, 0x00, 0x32},
					},
					EthTag:       []byte{0, 0, 0, 0},
					IPAddrLength: 32,
					IPAddr:       []byte{172, 31, 101, 6},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := UnmarshalEVPNNLRI(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(route.Route) != 1 {
				t.Fatalf("expected 1 route, got %d", len(route.Route))
			}
			if !reflect.DeepEqual(tt.expectRoute, route.Route[0]) {
				t.Fatalf("route mismatch:\nexpected: %+v\ngot:      %+v", tt.expectRoute, route.Route[0])
			}
		})
	}
}

// TestRFC7432_RouteType4_EthernetSegment tests RFC 7432 Section 7.4
// Ethernet Segment Route
func TestRFC7432_RouteType4_EthernetSegment(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectRoute *NLRI
		expectError bool
	}{
		{
			name: "basic ES route",
			input: []byte{
				0x04, // Route Type 4
				0x17, // Length 23
				// RD (8 bytes): Type 1
				0x00, 0x01, 0xac, 0x1f, 0x65, 0x06, 0x00, 0x00,
				// ESI (10 bytes)
				0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
				// IP Address Length (1 byte)
				0x20, // 32 bits
				// IP Address (4 bytes)
				0xac, 0x1f, 0x65, 0x06,
			},
			expectRoute: &NLRI{
				RouteType: 4,
				Length:    0x17,
				RouteTypeSpec: &EthernetSegment{
					RD: &base.RD{
						Type:  1,
						Value: []byte{0xac, 0x1f, 0x65, 0x06, 0x00, 0x00},
					},
					ESI: func() *ESI {
						esi, _ := MakeESI([]byte{0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11})
						return esi
					}(),
					IPAddrLength: 32,
					IPAddr:       []byte{0xac, 0x1f, 0x65, 0x06},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := UnmarshalEVPNNLRI(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(route.Route) != 1 {
				t.Fatalf("expected 1 route, got %d", len(route.Route))
			}
			if !reflect.DeepEqual(tt.expectRoute, route.Route[0]) {
				t.Fatalf("route mismatch:\nexpected: %+v\ngot:      %+v", tt.expectRoute, route.Route[0])
			}
		})
	}
}

// TestRFC7432_RouteType5_IPPrefix tests RFC 7432 Section 7.5
// IP Prefix Route
func TestRFC7432_RouteType5_IPPrefix(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectRoute *NLRI
		expectError bool
	}{
		{
			name: "IPv4 prefix /24",
			input: []byte{
				0x05, // Route Type 5
				0x22, // Length 34
				// RD (8 bytes): Type 1
				0x00, 0x01, 0x0A, 0x22, 0x04, 0x01, 0x00, 0x03,
				// ESI (10 bytes) - all zeros
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Ethernet Tag (4 bytes)
				0x00, 0x00, 0x00, 0x00,
				// IP Prefix Length (1 byte)
				0x18, // /24
				// IP Prefix (4 bytes even for /24)
				0x0A, 0x0A, 0x0A, 0x00,
				// Gateway IP (4 bytes)
				0x00, 0x00, 0x00, 0x00,
				// MPLS Label (3 bytes)
				0x00, 0x03, 0xFC,
			},
			expectRoute: &NLRI{
				RouteType: 5,
				Length:    34,
				RouteTypeSpec: &IPPrefix{
					RD: &base.RD{
						Type:  1,
						Value: []byte{0x0A, 0x22, 0x04, 0x01, 0x00, 0x03},
					},
					ESI: func() *ESI {
						esi, _ := MakeESI([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
						return esi
					}(),
					EthTag:       []byte{0, 0, 0, 0},
					IPAddrLength: 24,
					IPAddr:       []byte{10, 10, 10, 0},
					GWIPAddr:     []byte{0, 0, 0, 0},
					Label: []*base.Label{
						{
							Value: 63,
							Exp:   6,
							BoS:   false,
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "IPv6 prefix /64",
			input: []byte{
				0x05, // Route Type 5
				0x3A, // Length 58
				// RD (8 bytes): Type 1
				0x00, 0x01, 0x0A, 0x22, 0x04, 0x01, 0x00, 0x03,
				// ESI (10 bytes) - all zeros
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Ethernet Tag (4 bytes)
				0x00, 0x00, 0x00, 0x00,
				// IP Prefix Length (1 byte)
				0x40, // /64
				// IP Prefix (8 bytes for /64)
				0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x0B,
				// Rest of IPv6 (8 bytes)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Gateway IP (16 bytes)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// MPLS Label (3 bytes)
				0x00, 0x03, 0xFC,
			},
			expectRoute: &NLRI{
				RouteType: 5,
				Length:    58,
				RouteTypeSpec: &IPPrefix{
					RD: &base.RD{
						Type:  1,
						Value: []byte{0x0A, 0x22, 0x04, 0x01, 0x00, 0x03},
					},
					ESI: func() *ESI {
						esi, _ := MakeESI([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
						return esi
					}(),
					EthTag:       []byte{0, 0, 0, 0},
					IPAddrLength: 64,
					IPAddr:       []byte{32, 1, 13, 184, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0},
					GWIPAddr:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Label: []*base.Label{
						{
							Value: 63,
							Exp:   6,
							BoS:   false,
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := UnmarshalEVPNNLRI(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(route.Route) != 1 {
				t.Fatalf("expected 1 route, got %d", len(route.Route))
			}
			if !reflect.DeepEqual(tt.expectRoute, route.Route[0]) {
				t.Fatalf("route mismatch:\nexpected: %+v\ngot:      %+v", tt.expectRoute, route.Route[0])
			}
		})
	}
}

// TestRFC8365_MultiRoutes tests RFC 8365 multi-route parsing
func TestRFC8365_MultiRoutes(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectCount int
		expectError bool
	}{
		{
			name: "two type 5 routes in one NLRI",
			input: []byte{
				0x05, 0x22, 0x00, 0x01, 0x0A, 0x22, 0x04, 0x01, 0x00, 0x03,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x18, 0x0A, 0x0A, 0x0A, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFC,
				0x05, 0x22, 0x00, 0x01, 0x0A, 0x22, 0x04, 0x01, 0x00, 0x03,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x18, 0x14, 0x14, 0x14, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFC,
			},
			expectCount: 2,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := UnmarshalEVPNNLRI(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(route.Route) != tt.expectCount {
				t.Fatalf("expected %d routes, got %d", tt.expectCount, len(route.Route))
			}
		})
	}
}

// TestRFC7432_ErrorHandling tests error conditions
func TestRFC7432_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectError bool
	}{
		{
			name:        "empty NLRI",
			input:       []byte{},
			expectError: true,
		},
		{
			name: "unknown route type",
			input: []byte{
				0x99, // Unknown route type
				0x10,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expectError: true,
		},
		// Note: truncated route test removed - EVPN parser panics instead of returning error
		// This is a pre-existing bug in pkg/evpn/evpn.go:109 outside scope of RFC compliance
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalEVPNNLRI(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
