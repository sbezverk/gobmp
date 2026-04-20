package ls

import (
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/gobmp/pkg/te"
)

func TestLSNLRI71(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		nlri     NLRI71
		fail     bool
		elements []Element
	}{
		{
			name:  "ls node update",
			input: []byte{0x00, 0x01, 0x00, 0x27, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1A, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			fail:  false,
			elements: []Element{
				{
					Type: 1,
					LS:   &base.NodeNLRI{},
				},
			},
		},
		{
			name:  "ls link update",
			input: []byte{0x00, 0x02, 0x00, 0x73, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1A, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x01, 0x00, 0x1A, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x05, 0x00, 0x10, 0xFC, 0x00, 0xDD, 0xDD, 0x00, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x06, 0x00, 0x10, 0xFC, 0x00, 0xDD, 0xDD, 0x00, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x07, 0x00, 0x02, 0x00, 0x02},
			fail:  false,
			elements: []Element{
				{
					Type: 2,
					LS:   &base.LinkNLRI{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := UnmarshalLSNLRI71(tt.input, false)
			if err != nil && !tt.fail {
				t.Fatalf("test should succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatalf("test should fail but succeeded")
			}
			if err != nil {
				return
			}
			for i, e := range n.NLRI {
				if tt.elements[i].Type != e.Type {
					t.Fatalf("computed %d and expected %d nlri types do not match", e.Type, tt.elements[i].Type)
				}
				switch tt.elements[i].Type {
				case 1:
					n, ok := e.LS.(*base.NodeNLRI)
					if !ok {
						t.Fatalf("Unrecognzed NodeNLRI object")
					}
					t.Logf("Node: %+v", n)
					t.Logf("Node Descriptor: %+v", n.LocalNode)
				case 2:
					l, ok := e.LS.(*base.LinkNLRI)
					if !ok {
						t.Fatalf("Unrecognzed LinkNLRI object")
					}
					t.Logf("Link: %+v", l)
					t.Logf("Local Node Descriptor: %+v", l.LocalNode)
					t.Logf("Remote Node Descriptor: %+v", l.RemoteNode)
				case 3:
					fallthrough
				case 4:
					t.Logf("NLRI element: %+v", e.LS.(*base.PrefixNLRI))
				case 5:
					t.Logf("NLRI element: %+v", e.LS.(*te.NLRI))
				case 6:
					t.Logf("NLRI element: %+v", e.LS.(*srv6.SIDNLRI))
				default:
					t.Fatalf("non supported NLRI type: %d", tt.elements[i].Type)
				}

			}
		})
	}
}

func TestUnmarshalLSNLRI71_TruncatedHeader(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "1 byte", input: []byte{0x00}},
		{name: "2 bytes", input: []byte{0x00, 0x01}},
		{name: "3 bytes", input: []byte{0x00, 0x01, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalLSNLRI71(tt.input, false)
			if err == nil {
				t.Fatal("expected error for truncated TLV header")
			}
			if !strings.Contains(err.Error(), "truncated") {
				t.Errorf("expected truncation error, got: %v", err)
			}
		})
	}
}

func TestUnmarshalLSNLRI71_ZeroLengthTLV(t *testing.T) {
	// Type=1 (Node), Length=0 — must not cause infinite loop
	input := []byte{
		0x00, 0x01, // Type: 1
		0x00, 0x00, // Length: 0
	}
	_, err := UnmarshalLSNLRI71(input, false)
	if err == nil {
		t.Fatal("expected error for zero-length TLV")
	}
	if !strings.Contains(err.Error(), "zero length") {
		t.Errorf("expected zero length error, got: %v", err)
	}
}

func TestUnmarshalLSNLRI71_TruncatedValue(t *testing.T) {
	// Type=1 (Node), Length=100 but only 2 bytes of value
	input := []byte{
		0x00, 0x01, // Type: 1 (Node NLRI)
		0x00, 0x64, // Length: 100
		0x00, 0x00, // Only 2 bytes
	}
	_, err := UnmarshalLSNLRI71(input, false)
	if err == nil {
		t.Fatal("expected error for truncated TLV value")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("expected truncation error, got: %v", err)
	}
}

// TestUnmarshalLSNLRI71_AddPath verifies that when Add Path (RFC 7911) is enabled
// for BGP-LS SAFI 71, the leading 4-byte Path-ID is consumed and stored in
// NLRI71.PathID rather than being misinterpreted as an NLRI TLV.
// This covers the real-world case reported where IOS-XR sends Path-ID=1
// prepended to a Link NLRI (IS-IS L1, local 01:68:02:54:00:11, remote 01:68:02:54:00:01).
func TestUnmarshalLSNLRI71_AddPath(t *testing.T) {
	input := []byte{
		// Add Path Path-ID = 1 (RFC 7911)
		0x00, 0x00, 0x00, 0x01,
		// NLRI Type=2 (Link NLRI), Length=85
		0x00, 0x02, 0x00, 0x55,
		// Protocol-ID=1 (IS-IS L1), Identifier=0x0000000000000020
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
		// Local Node Descriptors (type=256, len=26)
		0x01, 0x00, 0x00, 0x1a,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xea, // AS=65002
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // BGP-LS ID=0
		0x02, 0x03, 0x00, 0x06, 0x01, 0x68, 0x02, 0x54, 0x00, 0x11, // Router-ID
		// Remote Node Descriptors (type=257, len=26)
		0x01, 0x01, 0x00, 0x1a,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xea, // AS=65002
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // BGP-LS ID=0
		0x02, 0x03, 0x00, 0x06, 0x01, 0x68, 0x02, 0x54, 0x00, 0x01, // Router-ID
		// IPv4 Interface Address (type=259, len=4): 192.168.66.1
		0x01, 0x03, 0x00, 0x04, 0xc0, 0xa8, 0x42, 0x01,
		// IPv4 Neighbor Address (type=260, len=4): 192.168.66.2
		0x01, 0x04, 0x00, 0x04, 0xc0, 0xa8, 0x42, 0x02,
	}
	nlri, err := UnmarshalLSNLRI71(input, true)
	if err != nil {
		t.Fatalf("UnmarshalLSNLRI71 with Add Path failed: %v", err)
	}
	if nlri.PathID != 1 {
		t.Fatalf("expected PathID=1, got %d", nlri.PathID)
	}
	if len(nlri.NLRI) != 1 {
		t.Fatalf("expected 1 NLRI element, got %d", len(nlri.NLRI))
	}
	if nlri.NLRI[0].Type != 2 {
		t.Fatalf("expected Link NLRI type 2, got %d", nlri.NLRI[0].Type)
	}
	link, ok := nlri.NLRI[0].LS.(*base.LinkNLRI)
	if !ok {
		t.Fatalf("expected *base.LinkNLRI, got %T", nlri.NLRI[0].LS)
	}
	if link.LocalNode == nil {
		t.Fatal("LocalNode should not be nil")
	}
	if link.RemoteNode == nil {
		t.Fatal("RemoteNode should not be nil")
	}
	t.Logf("Add Path Link NLRI: PathID=%d local=%+v remote=%+v", nlri.PathID, link.LocalNode, link.RemoteNode)
}

// TestUnmarshalLSNLRI71_Type3_IPv4Prefix covers the case=3 (IPv4 Prefix NLRI) branch.
func TestUnmarshalLSNLRI71_Type3_IPv4Prefix(t *testing.T) {
	// Type=3 (IPv4 Prefix NLRI), wrapping a valid PrefixNLRI payload (from base package test data).
	// Protocol-ID=2, Identifier=0, LocalNode (AS+BGPID+RouterID), IPv4 Prefix 9.0.203/24
	prefixVal := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // proto=2, ident=0
		0x01, 0x00, 0x00, 0x1a, // LocalNode desc type=256, len=26
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, // AS=5070
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // BGP-LS ID=0
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93, // Router-ID
		0x01, 0x09, 0x00, 0x04, 0x18, 0x09, 0x00, 0xcb, // PrefixDesc type=265, len=4: /24 9.0.203
	}
	hdr := []byte{0x00, 0x03, 0x00, byte(len(prefixVal))}
	input := append(hdr, prefixVal...)
	nlri, err := UnmarshalLSNLRI71(input, false)
	if err != nil {
		t.Fatalf("UnmarshalLSNLRI71 type 3 failed: %v", err)
	}
	if len(nlri.NLRI) != 1 || nlri.NLRI[0].Type != 3 {
		t.Fatalf("expected NLRI type 3, got %v", nlri.NLRI)
	}
	if _, ok := nlri.NLRI[0].LS.(*base.PrefixNLRI); !ok {
		t.Fatalf("expected *base.PrefixNLRI, got %T", nlri.NLRI[0].LS)
	}
}

// TestUnmarshalLSNLRI71_Type4_IPv6Prefix covers the case=4 (IPv6 Prefix NLRI) branch.
func TestUnmarshalLSNLRI71_Type4_IPv6Prefix(t *testing.T) {
	// Type=4 (IPv6 Prefix NLRI), wrapping a valid PrefixNLRI payload.
	// Protocol-ID=2, Identifier=0, LocalNode, IPv6 prefix 7800:9000:3400::/48
	prefixVal := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // proto=2, ident=0
		0x01, 0x00, 0x00, 0x1a, // LocalNode desc type=256, len=26
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, // AS=5070
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // BGP-LS ID=0
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93, // Router-ID
		// MT-ID type=263, len=2
		0x01, 0x07, 0x00, 0x02, 0x00, 0x02,
		// IPv6 Prefix type=265, len=16
		0x01, 0x09, 0x00, 0x10,
		0x78, 0x00, 0x90, 0x00, 0x34, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	hdr := []byte{0x00, 0x04, 0x00, byte(len(prefixVal))}
	input := append(hdr, prefixVal...)
	nlri, err := UnmarshalLSNLRI71(input, false)
	if err != nil {
		t.Fatalf("UnmarshalLSNLRI71 type 4 failed: %v", err)
	}
	if len(nlri.NLRI) != 1 || nlri.NLRI[0].Type != 4 {
		t.Fatalf("expected NLRI type 4, got %v", nlri.NLRI)
	}
	if _, ok := nlri.NLRI[0].LS.(*base.PrefixNLRI); !ok {
		t.Fatalf("expected *base.PrefixNLRI, got %T", nlri.NLRI[0].LS)
	}
}

// TestUnmarshalLSNLRI71_Type5_TEPolicy covers the case=5 (TE Policy NLRI) branch.
func TestUnmarshalLSNLRI71_Type5_TEPolicy(t *testing.T) {
	// Valid TE Policy NLRI payload (from te package test data).
	tePolicyVal := []byte{
		0x09,                                           // ProtocolID=9 (SR)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Identifier=0
		0x01, 0x00, 0x00, 0x10, // Node Descriptor type=256, len=16
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, // TLV 512 ASN=65000
		0x02, 0x04, 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x01, // TLV 516 BGP Router-ID
	}
	hdr := []byte{0x00, 0x05, 0x00, byte(len(tePolicyVal))}
	input := append(hdr, tePolicyVal...)
	nlri, err := UnmarshalLSNLRI71(input, false)
	if err != nil {
		t.Fatalf("UnmarshalLSNLRI71 type 5 failed: %v", err)
	}
	if len(nlri.NLRI) != 1 || nlri.NLRI[0].Type != 5 {
		t.Fatalf("expected NLRI type 5, got %v", nlri.NLRI)
	}
	if _, ok := nlri.NLRI[0].LS.(*te.NLRI); !ok {
		t.Fatalf("expected *te.NLRI, got %T", nlri.NLRI[0].LS)
	}
}

// TestUnmarshalLSNLRI71_Type6_SRv6SID covers the case=6 (SRv6 SID NLRI) branch.
func TestUnmarshalLSNLRI71_Type6_SRv6SID(t *testing.T) {
	// Valid SRv6 SID NLRI payload (from srv6 package test data).
	srv6Val := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // proto=2, ident=0
		0x01, 0x00, 0x00, 0x1a, // LocalNode desc type=256, len=26
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, // AS=5070
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // BGP-LS ID=0
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93, // Router-ID
		// MT-ID type=263, len=2
		0x01, 0x07, 0x00, 0x02, 0x00, 0x02,
		// SRv6 SID type=518, len=16
		0x02, 0x06, 0x00, 0x10,
		0x01, 0x92, 0x01, 0x68, 0x00, 0x93, 0x00, 0x00,
		0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	hdr := []byte{0x00, 0x06, 0x00, byte(len(srv6Val))}
	input := append(hdr, srv6Val...)
	nlri, err := UnmarshalLSNLRI71(input, false)
	if err != nil {
		t.Fatalf("UnmarshalLSNLRI71 type 6 failed: %v", err)
	}
	if len(nlri.NLRI) != 1 || nlri.NLRI[0].Type != 6 {
		t.Fatalf("expected NLRI type 6, got %v", nlri.NLRI)
	}
	if _, ok := nlri.NLRI[0].LS.(*srv6.SIDNLRI); !ok {
		t.Fatalf("expected *srv6.SIDNLRI, got %T", nlri.NLRI[0].LS)
	}
}

// TestUnmarshalLSNLRI71_UnmarshalErrors covers error propagation from each type-specific unmarshaler.
func TestUnmarshalLSNLRI71_UnmarshalErrors(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name: "type 1 node nlri bad payload",
			// Type=1, Length=1, Value=0x00 — too short for NodeNLRI
			input: []byte{0x00, 0x01, 0x00, 0x01, 0x00},
		},
		{
			name: "type 2 link nlri bad payload",
			// Type=2, Length=1, Value=0x00 — too short for LinkNLRI
			input: []byte{0x00, 0x02, 0x00, 0x01, 0x00},
		},
		{
			name: "type 3 prefix nlri bad payload",
			// Type=3, Length=1, Value=0x00 — too short for PrefixNLRI
			input: []byte{0x00, 0x03, 0x00, 0x01, 0x00},
		},
		{
			name: "type 4 prefix nlri bad payload",
			// Type=4, Length=1, Value=0x00 — too short for PrefixNLRI
			input: []byte{0x00, 0x04, 0x00, 0x01, 0x00},
		},
		{
			name: "type 5 te policy nlri bad payload",
			// Type=5, Length=1, Value=0x00 — too short for TEPolicyNLRI
			input: []byte{0x00, 0x05, 0x00, 0x01, 0x00},
		},
		{
			name: "type 6 srv6 sid nlri bad payload",
			// Type=6, Length=1, Value=0x00 — too short for SRv6SIDNLRI
			input: []byte{0x00, 0x06, 0x00, 0x01, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalLSNLRI71(tt.input, false)
			if err == nil {
				t.Fatal("expected error for bad payload, got nil")
			}
		})
	}
}
