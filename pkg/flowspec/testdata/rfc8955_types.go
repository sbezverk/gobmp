// Package testdata contains RFC 8955/8956 compliant synthetic test data for FlowSpec
//
// All test data is generated according to RFC 8955/8956 specifications:
// - Type 9: TCP Flags (RFC 8955 Section 4.2.4)
// - Type 12: Fragment (RFC 8955 Section 4.2.6)
// - Multi-component rules (HTTP filtering, SSH blocking, DDoS mitigation)
package testdata

// RFC8955TCPFlagsTestData contains TCP Flags (Type 9) test data
var RFC8955TCPFlagsTestData = struct {
	// Single flag tests
	FIN []byte // FIN flag only
	SYN []byte // SYN flag only (connection establishment)
	RST []byte // RST flag only (connection reset)
	PSH []byte // PSH flag only (push data)
	ACK []byte // ACK flag only
	URG []byte // URG flag only (urgent)

	// Common flag combinations
	SYNACK    []byte // SYN+ACK (connection accept)
	FINACK    []byte // FIN+ACK (graceful close)
	PSHACK    []byte // PSH+ACK (data transfer)
	RSTACK    []byte // RST+ACK (abort connection)
	SYNOnly   []byte // Match SYN without ACK (new connections)
	NotSYN    []byte // Match anything except SYN
	AllFlags  []byte // All flags set
	NoFlags   []byte // No flags set

	// Operator tests
	TCPFlagsMatch    []byte // Exact match operator
	TCPFlagsNotMatch []byte // Not match operator
	TCPFlagsAnd      []byte // Bitwise AND operator

	// Real-world filtering scenarios
	BlockSYNFlood []byte // Block SYN without ACK (SYN flood protection)
	AllowEstab    []byte // Allow established connections (ACK set)
	BlockXmasTree []byte // Block Xmas scan (FIN+PSH+URG)
	BlockNullScan []byte // Block NULL scan (no flags)
}{
	// Type 9 format: [Length][Type=9][Operator][Value]
	// TCP Flags byte: Bit 0=FIN, 1=SYN, 2=RST, 3=PSH, 4=ACK, 5=URG

	// Single flags
	FIN: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x01,       // Value: FIN (0000 0001)
	},
	SYN: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x02,       // Value: SYN (0000 0010)
	},
	RST: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x04,       // Value: RST (0000 0100)
	},
	PSH: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x08,       // Value: PSH (0000 1000)
	},
	ACK: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x10,       // Value: ACK (0001 0000)
	},
	URG: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x20,       // Value: URG (0010 0000)
	},

	// Common combinations
	SYNACK: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x12,       // Value: SYN+ACK (0001 0010)
	},
	FINACK: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x11,       // Value: FIN+ACK (0001 0001)
	},
	PSHACK: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x18,       // Value: PSH+ACK (0001 1000)
	},
	RSTACK: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x14,       // Value: RST+ACK (0001 0100)
	},

	// Operator variants
	SYNOnly: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x02,       // Value: SYN only (0000 0010)
	},
	NotSYN: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x82,       // Operator: EOL=1, Length=1, NOT bit set
		0x02,       // Value: NOT SYN
	},
	AllFlags: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x3F,       // Value: All 6 flags (0011 1111)
	},
	NoFlags: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: EOL=1, Length=1, Match
		0x00,       // Value: No flags (0000 0000)
	},

	// Security filtering scenarios
	BlockSYNFlood: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: Match (SYN without ACK)
		0x02,       // Value: SYN only
	},
	AllowEstab: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: Match (ACK must be set)
		0x10,       // Value: ACK
	},
	BlockXmasTree: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: Match
		0x29,       // Value: FIN+PSH+URG (0010 1001)
	},
	BlockNullScan: []byte{
		0x04,       // Length: 4 bytes
		0x09,       // Type: TCP Flags
		0x81,       // Operator: Match
		0x00,       // Value: No flags (NULL scan)
	},
}

// RFC8955FragmentTestData contains Fragment (Type 12) test data
var RFC8955FragmentTestData = struct {
	// Individual fragment flags
	IsFragment    []byte // IsF bit (packet is a fragment)
	FirstFragment []byte // FF bit (first fragment)
	LastFragment  []byte // LF bit (last fragment)
	DontFragment  []byte // DF bit (don't fragment flag set)

	// Combinations
	NotFirstFragment []byte // IsF + NOT FF (middle/last fragments)
	OnlyFirstFrag    []byte // FF bit only
	OnlyLastFrag     []byte // LF bit only
	NotFragment      []byte // NOT IsF (complete packets only)

	// Real-world filtering
	BlockFragments     []byte // Block all fragmented packets
	AllowOnlyFirst     []byte // Allow only first fragments
	BlockTinyFragments []byte // Block fragments (for Teardrop/Bonk attacks)
}{
	// Type 12 format: [Length][Type=12][Operator][Value]
	// Fragment flags: Bit 0=LF (Last Fragment), 1=FF (First Fragment),
	//                 2=IsF (Is a Fragment), 3=DF (Don't Fragment)

	IsFragment: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x81,       // Operator: EOL=1, Length=1, Match
		0x04,       // Value: IsF bit (0000 0100)
	},
	FirstFragment: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x81,       // Operator: EOL=1, Length=1, Match
		0x02,       // Value: FF bit (0000 0010)
	},
	LastFragment: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x81,       // Operator: EOL=1, Length=1, Match
		0x01,       // Value: LF bit (0000 0001)
	},
	DontFragment: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x81,       // Operator: EOL=1, Length=1, Match
		0x08,       // Value: DF bit (0000 1000)
	},

	// Combinations
	NotFirstFragment: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x81,       // Operator: Match
		0x04,       // Value: IsF=1, FF=0 (middle/last fragment)
	},
	OnlyFirstFrag: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x81,       // Operator: Match
		0x06,       // Value: IsF=1, FF=1 (0000 0110)
	},
	OnlyLastFrag: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x81,       // Operator: Match
		0x05,       // Value: IsF=1, LF=1 (0000 0101)
	},
	NotFragment: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x82,       // Operator: NOT bit set
		0x04,       // Value: NOT IsF (complete packets)
	},

	// Security scenarios
	BlockFragments: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x81,       // Operator: Match
		0x04,       // Value: IsF=1 (any fragment)
	},
	AllowOnlyFirst: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x81,       // Operator: Match
		0x06,       // Value: IsF=1, FF=1
	},
	BlockTinyFragments: []byte{
		0x04,       // Length: 4 bytes
		0x0C,       // Type: Fragment
		0x81,       // Operator: Match (used with packet length)
		0x04,       // Value: IsF=1
	},
}

// RFC8955MultiComponentRules contains complex multi-component FlowSpec rules
var RFC8955MultiComponentRules = struct {
	// Security rules
	BlockSYNFloodHTTP  []byte // Block SYN flood to port 80
	BlockXmasSSH       []byte // Block Xmas scan to SSH
	AllowEstabHTTPS    []byte // Allow established HTTPS connections
	BlockFragmentedICMP []byte // Block fragmented ICMP (Ping of Death)

	// Traffic shaping
	LimitP2PTraffic    []byte // Limit high port traffic
	PrioritizeVoIP     []byte // Prioritize VoIP (DSCP EF)
	BlockLargeFragments []byte // Block large fragmented packets
}{
	// Dest Prefix 0.0.0.0/0 + TCP + Port 80 + TCP Flags SYN (no ACK)
	BlockSYNFloodHTTP: []byte{
		0x12,                  // Length: 18 bytes total
		0x01, 0x00,            // Type 1: Dest Prefix /0 (any)
		0x03, 0x81, 0x06,      // Type 3: IP Protocol TCP
		0x05, 0x81, 0x00, 0x50, // Type 5: Dest Port 80
		0x09, 0x91, 0x02,      // Type 9: TCP Flags SYN only
	},

	// Dest Prefix SSH server + TCP + Port 22 + TCP Flags (FIN+PSH+URG)
	BlockXmasSSH: []byte{
		0x16,                         // Length: 22 bytes
		0x01, 0x20, 192, 0, 2, 0,     // Type 1: Dest 192.0.2.0/32
		0x03, 0x81, 0x06,             // Type 3: TCP
		0x05, 0x81, 0x00, 0x16,       // Type 5: Port 22
		0x09, 0x91, 0x29,             // Type 9: FIN+PSH+URG
	},

	// Dest Prefix 0.0.0.0/0 + TCP + Port 443 + TCP Flags ACK
	AllowEstabHTTPS: []byte{
		0x13,                   // Length: 19 bytes
		0x01, 0x00,             // Type 1: Dest Prefix /0
		0x03, 0x81, 0x06,       // Type 3: TCP
		0x05, 0x81, 0x01, 0xBB, // Type 5: Port 443
		0x09, 0x91, 0x10,       // Type 9: ACK flag
	},

	// Dest Prefix 0.0.0.0/0 + ICMP + Fragment IsF
	BlockFragmentedICMP: []byte{
		0x0D,             // Length: 13 bytes
		0x01, 0x00,       // Type 1: Dest Prefix /0
		0x03, 0x81, 0x01, // Type 3: ICMP
		0x0C, 0x91, 0x04, // Type 12: Fragment IsF
	},

	// Source Port >1024 + Dest Port >1024 (P2P traffic)
	LimitP2PTraffic: []byte{
		0x10,                   // Length: 16 bytes
		0x06, 0x85, 0x04, 0x00, // Type 6: Source Port >1024 (0x0400)
		0x05, 0x85, 0x04, 0x00, // Type 5: Dest Port >1024
	},

	// DSCP EF (46) + UDP (VoIP priority)
	PrioritizeVoIP: []byte{
		0x0B,             // Length: 11 bytes
		0x03, 0x81, 0x11, // Type 3: UDP
		0x0B, 0x91, 0x2E, // Type 11: DSCP 46 (EF)
	},

	// Packet Length >1500 + Fragment IsF (large fragments)
	BlockLargeFragments: []byte{
		0x0E,                   // Length: 14 bytes
		0x0A, 0x85, 0x05, 0xDC, // Type 10: Packet Length >1500
		0x0C, 0x91, 0x04,       // Type 12: Fragment IsF
	},
}
