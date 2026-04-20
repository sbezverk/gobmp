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
			n, err := UnmarshalLSNLRI71(tt.input)
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
			_, err := UnmarshalLSNLRI71(tt.input)
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
	_, err := UnmarshalLSNLRI71(input)
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
	_, err := UnmarshalLSNLRI71(input)
	if err == nil {
		t.Fatal("expected error for truncated TLV value")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("expected truncation error, got: %v", err)
	}
}

// TestUnmarshalLSNLRI71_VendorPrefix4Byte verifies that a 4-byte vendor-specific
// prefix (0x00000001) prepended before the standard NLRI TLVs is handled correctly.
// Some router implementations (e.g. IOS-XR) send BGP-LS NLRI data with these extra
// leading bytes before the standard RFC 7752 TLV structure.
// The actual NLRI from this real-world BGP UPDATE is a Link NLRI (IS-IS L1,
// local 01:68:02:54:00:11, remote 01:68:02:54:00:01).
func TestUnmarshalLSNLRI71_VendorPrefix4Byte(t *testing.T) {
	// 4-byte vendor prefix (00 00 00 01) + Link NLRI (type=2, len=85)
	input := []byte{
		// Vendor prefix (4 bytes)
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
	nlri, err := UnmarshalLSNLRI71(input)
	if err != nil {
		t.Fatalf("UnmarshalLSNLRI71 failed: %v", err)
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
	t.Logf("Link NLRI parsed: local=%+v remote=%+v", link.LocalNode, link.RemoteNode)
}
