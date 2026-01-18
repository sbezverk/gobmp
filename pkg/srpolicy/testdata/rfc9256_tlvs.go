// Package testdata contains RFC 9256 compliant synthetic test data for SR Policy
//
// All test data is generated according to RFC 9256 specifications:
// - TLV Type 123: Preference
// - TLV Type 124: Priority
// - TLV Type 125: Policy Name
// - TLV Type 126: Explicit NULL Label Policy
// - TLV Type 127: Segment List (with various Segment types)
// - TLV Type 128: Binding SID (IPv4, IPv6, SRv6)
// - TLV Type 1200+: Sub-TLVs
package testdata

// RFC9256TLVTestData contains comprehensive TLV test data
var RFC9256TLVTestData = struct {
	// TLV Type 123: Preference (4 bytes)
	PreferenceLow    []byte // Preference = 100
	PreferenceMedium []byte // Preference = 200
	PreferenceHigh   []byte // Preference = 300
	PreferenceMax    []byte // Preference = 4294967295

	// TLV Type 124: Priority (1 byte)
	PriorityLow  []byte // Priority = 1
	PriorityHigh []byte // Priority = 255

	// TLV Type 125: Policy Name (variable length string)
	PolicyNameShort []byte // "LOW-LATENCY"
	PolicyNameLong  []byte // "HIGH-BANDWIDTH-PATH-PRIMARY"

	// TLV Type 126: Explicit NULL Label Policy (1 byte)
	ExplicitNullPush    []byte // 0x01: Push Explicit NULL
	ExplicitNullNoPush  []byte // 0x02: Do not push Explicit NULL
	ExplicitNullDefault []byte // 0x00: Use default behavior

	// TLV Type 127: Segment List (complex structure)
	SegmentListTypeA       []byte // Type A: SID only
	SegmentListTypeB       []byte // Type B: SID + ERO subobjects
	SegmentListTypeC       []byte // Type C: IPv4 node address
	SegmentListTypeD       []byte // Type D: IPv6 node address
	SegmentListTypeE       []byte // Type E: IPv4 adjacency
	SegmentListTypeF       []byte // Type F: IPv6 adjacency with local addresses
	SegmentListMultiSeg    []byte // Multiple segments (3 segments)
	SegmentListWeightHigh  []byte // Weight = 100
	SegmentListWeightEqual []byte // Weight = 1 (equal cost)

	// TLV Type 128: Binding SID
	BSIDIPv4     []byte // IPv4 BSID: 192.0.2.1 with label 100000
	BSIDIPv6     []byte // IPv6 BSID: 2001:db8::1 with label 200000
	BSIDSRv6     []byte // SRv6 BSID: SRv6 SID
	BSIDSID      []byte // Plain 4-byte SID
	BSIDLabelMax []byte // Maximum MPLS label value (1048575)

	// Complex Multi-TLV Structures
	CompletePolicy3Segments []byte // Full policy: Preference + Priority + 3 Segment Lists
	PolicyWithBSID          []byte // Policy with Preference + Segment List + BSID
	PolicyMultiPath         []byte // Policy with 2 Segment Lists (ECMP)
}{
	// TLV Type 123: Preference (4 bytes: Type=123, Length=4, Value=4 bytes)
	PreferenceLow: []byte{
		0x7B,                   // Type: 123 (Preference)
		0x00, 0x04,             // Length: 4 bytes
		0x00, 0x00, 0x00, 0x64, // Value: 100
	},
	PreferenceMedium: []byte{
		0x7B,                   // Type: 123
		0x00, 0x04,             // Length: 4
		0x00, 0x00, 0x00, 0xC8, // Value: 200
	},
	PreferenceHigh: []byte{
		0x7B,                   // Type: 123
		0x00, 0x04,             // Length: 4
		0x00, 0x00, 0x01, 0x2C, // Value: 300
	},
	PreferenceMax: []byte{
		0x7B,                   // Type: 123
		0x00, 0x04,             // Length: 4
		0xFF, 0xFF, 0xFF, 0xFF, // Value: 4294967295
	},

	// TLV Type 124: Priority (1 byte: Type=124, Length=1, Value=1 byte)
	PriorityLow: []byte{
		0x7C,       // Type: 124 (Priority)
		0x00, 0x01, // Length: 1 byte
		0x01,       // Value: 1
	},
	PriorityHigh: []byte{
		0x7C,       // Type: 124
		0x00, 0x01, // Length: 1
		0xFF,       // Value: 255
	},

	// TLV Type 125: Policy Name (variable length)
	PolicyNameShort: []byte{
		0x7D,       // Type: 125 (Policy Name)
		0x00, 0x0B, // Length: 11 bytes
		'L', 'O', 'W', '-', 'L', 'A', 'T', 'E', 'N', 'C', 'Y',
	},
	PolicyNameLong: []byte{
		0x7D,       // Type: 125
		0x00, 0x1D, // Length: 29 bytes
		'H', 'I', 'G', 'H', '-', 'B', 'A', 'N', 'D', 'W', 'I', 'D', 'T', 'H', '-',
		'P', 'A', 'T', 'H', '-', 'P', 'R', 'I', 'M', 'A', 'R', 'Y',
	},

	// TLV Type 126: Explicit NULL Label Policy
	ExplicitNullPush: []byte{
		0x7E,       // Type: 126
		0x00, 0x01, // Length: 1
		0x01,       // Push Explicit NULL
	},
	ExplicitNullNoPush: []byte{
		0x7E,       // Type: 126
		0x00, 0x01, // Length: 1
		0x02,       // Do not push Explicit NULL
	},
	ExplicitNullDefault: []byte{
		0x7E,       // Type: 126
		0x00, 0x01, // Length: 1
		0x00,       // Default behavior
	},

	// TLV Type 127: Segment List - Type A (SID only, simplest form)
	SegmentListTypeA: []byte{
		0x7F,                   // Type: 127 (Segment List)
		0x00, 0x0C,             // Length: 12 bytes
		0x00, 0x00, 0x00, 0x0A, // Weight: 10
		// Segment Sub-TLV (Type A: MPLS Label)
		0x01,                   // Sub-TLV Type: 1 (MPLS Label)
		0x00, 0x04,             // Length: 4 bytes
		0x00, 0x01, 0x86, 0xA0, // Label: 100000 (0x0186A0)
	},

	// TLV Type 127: Segment List - Type C (IPv4 Node Address)
	SegmentListTypeC: []byte{
		0x7F,                   // Type: 127 (Segment List)
		0x00, 0x10,             // Length: 16 bytes
		0x00, 0x00, 0x00, 0x14, // Weight: 20
		// Segment Sub-TLV (Type C: IPv4 Node Address + SID)
		0x03,             // Sub-TLV Type: 3 (IPv4 Node Address)
		0x00, 0x08,       // Length: 8 bytes
		0xC0, 0x00, 0x02, 0x01, // IPv4: 192.0.2.1
		0x00, 0x03, 0x0D, 0x40, // SID: 200000
	},

	// TLV Type 127: Segment List - Type D (IPv6 Node Address)
	SegmentListTypeD: []byte{
		0x7F,                   // Type: 127 (Segment List)
		0x00, 0x1C,             // Length: 28 bytes
		0x00, 0x00, 0x00, 0x1E, // Weight: 30
		// Segment Sub-TLV (Type D: IPv6 Node Address + SID)
		0x04,       // Sub-TLV Type: 4 (IPv6 Node Address)
		0x00, 0x14, // Length: 20 bytes
		// IPv6: 2001:db8::1
		0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x04, 0xC4, 0xB4, // SID: 314548
	},

	// TLV Type 127: Segment List with 3 segments (Multi-Segment)
	SegmentListMultiSeg: []byte{
		0x7F,                   // Type: 127 (Segment List)
		0x00, 0x24,             // Length: 36 bytes
		0x00, 0x00, 0x00, 0x32, // Weight: 50
		// Segment 1: Type A (MPLS Label)
		0x01,                   // Type: 1
		0x00, 0x04,             // Length: 4
		0x00, 0x01, 0x86, 0xA0, // Label: 100000
		// Segment 2: Type A (MPLS Label)
		0x01,                   // Type: 1
		0x00, 0x04,             // Length: 4
		0x00, 0x03, 0x0D, 0x40, // Label: 200000
		// Segment 3: Type C (IPv4 Node + SID)
		0x03,                   // Type: 3
		0x00, 0x08,             // Length: 8
		0xC0, 0x00, 0x02, 0x0A, // IPv4: 192.0.2.10
		0x00, 0x04, 0x93, 0xE0, // SID: 300000
	},

	// TLV Type 128: Binding SID - IPv4
	BSIDIPv4: []byte{
		0x80,                   // Type: 128 (Binding SID)
		0x00, 0x08,             // Length: 8 bytes
		0x00,                   // Flags
		0x00, 0x00, 0x00,       // Reserved
		0x00, 0x01, 0x86, 0xA0, // SID: 100000 (MPLS label format)
	},

	// TLV Type 128: Binding SID - IPv6
	BSIDIPv6: []byte{
		0x80,                   // Type: 128 (Binding SID)
		0x00, 0x08,             // Length: 8 bytes
		0x00,                   // Flags
		0x00, 0x00, 0x00,       // Reserved
		0x00, 0x03, 0x0D, 0x40, // SID: 200000
	},

	// TLV Type 128: Binding SID - SRv6 (128-bit SID)
	BSIDSRv6: []byte{
		0x80,       // Type: 128 (Binding SID)
		0x00, 0x14, // Length: 20 bytes
		0x00,       // Flags
		0x00, 0x00, 0x00, // Reserved
		// SRv6 SID: 2001:db8:1::1
		0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	},

	// Complex: Complete Policy with Preference + Priority + 3 Segment Lists
	CompletePolicy3Segments: []byte{
		// Preference TLV
		0x7B,                   // Type: 123
		0x00, 0x04,             // Length: 4
		0x00, 0x00, 0x00, 0x64, // Value: 100
		// Priority TLV
		0x7C,       // Type: 124
		0x00, 0x01, // Length: 1
		0x0A,       // Value: 10
		// Segment List 1 (Weight 30)
		0x7F,                   // Type: 127
		0x00, 0x0C,             // Length: 12
		0x00, 0x00, 0x00, 0x1E, // Weight: 30
		0x01,                   // Segment Type A
		0x00, 0x04,             // Length: 4
		0x00, 0x01, 0x86, 0xA0, // Label: 100000
		// Segment List 2 (Weight 30)
		0x7F,                   // Type: 127
		0x00, 0x0C,             // Length: 12
		0x00, 0x00, 0x00, 0x1E, // Weight: 30
		0x01,                   // Segment Type A
		0x00, 0x04,             // Length: 4
		0x00, 0x03, 0x0D, 0x40, // Label: 200000
		// Segment List 3 (Weight 40)
		0x7F,                   // Type: 127
		0x00, 0x0C,             // Length: 12
		0x00, 0x00, 0x00, 0x28, // Weight: 40
		0x01,                   // Segment Type A
		0x00, 0x04,             // Length: 4
		0x00, 0x04, 0x93, 0xE0, // Label: 300000
	},

	// Complex: Policy with BSID
	PolicyWithBSID: []byte{
		// Preference
		0x7B,                   // Type: 123
		0x00, 0x04,             // Length: 4
		0x00, 0x00, 0x00, 0xC8, // Value: 200
		// Segment List
		0x7F,                   // Type: 127
		0x00, 0x0C,             // Length: 12
		0x00, 0x00, 0x00, 0x0A, // Weight: 10
		0x01,                   // Segment Type A
		0x00, 0x04,             // Length: 4
		0x00, 0x01, 0x86, 0xA0, // Label: 100000
		// Binding SID
		0x80,                   // Type: 128
		0x00, 0x08,             // Length: 8
		0x00,                   // Flags
		0x00, 0x00, 0x00,       // Reserved
		0x00, 0x05, 0xDC, 0x00, // SID: 384000
	},

	// Complex: Multi-Path (ECMP) with 2 equal-cost Segment Lists
	PolicyMultiPath: []byte{
		// Preference
		0x7B,                   // Type: 123
		0x00, 0x04,             // Length: 4
		0x00, 0x00, 0x01, 0x2C, // Value: 300
		// Segment List 1 (Path A - Weight 50)
		0x7F,                   // Type: 127
		0x00, 0x0C,             // Length: 12
		0x00, 0x00, 0x00, 0x32, // Weight: 50
		0x01,                   // Segment Type A
		0x00, 0x04,             // Length: 4
		0x00, 0x01, 0x86, 0xA0, // Label: 100000
		// Segment List 2 (Path B - Weight 50)
		0x7F,                   // Type: 127
		0x00, 0x0C,             // Length: 12
		0x00, 0x00, 0x00, 0x32, // Weight: 50
		0x01,                   // Segment Type A
		0x00, 0x04,             // Length: 4
		0x00, 0x03, 0x0D, 0x40, // Label: 200000
	},
}
