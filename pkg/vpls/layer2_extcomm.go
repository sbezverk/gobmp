package vpls

import (
	"encoding/binary"
	"fmt"
)

// Layer2InfoExtComm represents Layer2 Info Extended Community (Type 0x800A)
//
// RFC 4761 Section 3.2.4: Layer2 Info Extended Community
//
//	+------------------------------------+
//	| Extended Community Type (2 octets) | 0x800A
//	+------------------------------------+
//	|  Encapsulation Type (1 octet)      | 1-19 (see EncapType constants)
//	+------------------------------------+
//	|  Control Flags (1 octet)           | Bit 0: C, Bit 1: S
//	+------------------------------------+
//	|  Layer-2 MTU (2 octets)            |
//	+------------------------------------+
//	|  Reserved (2 octets)               | Must be 0
//	+------------------------------------+
type Layer2InfoExtComm struct {
	EncapType    uint8  // Encapsulation type (1-19)
	ControlWord  bool   // C flag: Control word required/preferred
	SequencedDel bool   // S flag: Sequenced delivery of frames
	MTU          uint16 // Layer-2 MTU in bytes
}

// Encapsulation Type values from RFC 4761 Section 3.2.4
const (
	EncapFrameRelayDLCI = 1  // Frame Relay DLCI
	EncapATMAAL5        = 2  // ATM AAL5 VCC transport
	EncapATMTransparent = 3  // ATM transparent cell transport
	EncapEthernet       = 4  // Ethernet (802.3)
	EncapVLAN           = 5  // VLAN (802.1Q)
	EncapHDLC           = 6  // HDLC
	EncapPPP            = 7  // PPP
	EncapSONETSDH       = 8  // SONET/SDH Circuit Emulation Service
	EncapATMnto1VCC     = 9  // ATM n-to-one VCC cell transport
	EncapATMnto1VPC     = 10 // ATM n-to-one VPC cell transport
	EncapIPLayer2       = 11 // IP Layer 2 Transport
	EncapEthernetVLAN   = 19 // Ethernet VLAN (802.1Q)
)

// EncapTypeToString returns human-readable encapsulation type
func EncapTypeToString(encapType uint8) string {
	switch encapType {
	case EncapFrameRelayDLCI:
		return "Frame Relay DLCI"
	case EncapATMAAL5:
		return "ATM AAL5 VCC transport"
	case EncapATMTransparent:
		return "ATM transparent cell transport"
	case EncapEthernet:
		return "Ethernet (802.3)"
	case EncapVLAN:
		return "VLAN (802.1Q)"
	case EncapHDLC:
		return "HDLC"
	case EncapPPP:
		return "PPP"
	case EncapSONETSDH:
		return "SONET/SDH Circuit Emulation Service"
	case EncapATMnto1VCC:
		return "ATM n-to-one VCC cell transport"
	case EncapATMnto1VPC:
		return "ATM n-to-one VPC cell transport"
	case EncapIPLayer2:
		return "IP Layer 2 Transport"
	case EncapEthernetVLAN:
		return "Ethernet VLAN (802.1Q)"
	default:
		return fmt.Sprintf("Unknown (%d)", encapType)
	}
}

// ParseLayer2InfoExtComm parses Layer2 Info Extended Community (Type 0x800A)
// Input: 8-byte extended community value (excludes the Type field)
//
// Returns Layer2InfoExtComm or error if parsing fails
func ParseLayer2InfoExtComm(b []byte) (*Layer2InfoExtComm, error) {
	// Extended Community is 8 bytes total
	if len(b) != 8 {
		return nil, fmt.Errorf("Layer2 Info Extended Community must be 8 bytes, got %d", len(b))
	}

	extComm := &Layer2InfoExtComm{}

	// Byte 0-1: Type (0x800A) - should be validated by caller
	// We skip type field and parse value starting at offset 2

	// Byte 2: Encapsulation Type
	extComm.EncapType = b[2]

	// Byte 3: Control Flags
	// Bit 0 (0x01): C flag - Control word required/preferred
	// Bit 1 (0x02): S flag - Sequenced delivery
	flags := b[3]
	extComm.ControlWord = (flags & 0x01) != 0
	extComm.SequencedDel = (flags & 0x02) != 0

	// Bytes 4-5: Layer-2 MTU (2 bytes, big endian)
	extComm.MTU = binary.BigEndian.Uint16(b[4:6])

	// Bytes 6-7: Reserved (must be 0 per RFC)
	reserved := binary.BigEndian.Uint16(b[6:8])
	if reserved != 0 {
		return nil, fmt.Errorf("reserved field must be 0, got 0x%04x", reserved)
	}

	return extComm, nil
}

// String returns a human-readable representation of the Layer2 Info Extended Community
func (l *Layer2InfoExtComm) String() string {
	cFlag := "none"
	if l.ControlWord {
		cFlag = "C"
	}
	sFlag := ""
	if l.SequencedDel {
		if cFlag != "none" {
			sFlag = ",S"
		} else {
			sFlag = "S"
			cFlag = ""
		}
	}

	flags := cFlag + sFlag
	if flags == "" {
		flags = "none"
	}

	return fmt.Sprintf("L2-Info: Encap=%s, Flags=%s, MTU=%d",
		EncapTypeToString(l.EncapType),
		flags,
		l.MTU,
	)
}

// RouteTarget represents a Route Target Extended Community
//
// RFC 4360 Section 4: Route Target Community
// Three types supported:
//   - Type 0x0002: 2-octet AS Specific (AS:assigned-number)
//   - Type 0x0102: IPv4 Address Specific (IPv4:assigned-number)
//   - Type 0x0202: 4-octet AS Specific (AS4:assigned-number)
type RouteTarget struct {
	Type        uint16 // 0x0002, 0x0102, or 0x0202
	AS          uint32 // AS number (for Type 0x0002 and 0x0202)
	IPv4        string // IPv4 address (for Type 0x0102)
	AssignedNum uint32 // Assigned number
}

// ParseRouteTarget parses Route Target Extended Community
// Input: 8-byte extended community value
//
// Returns RouteTarget or error if parsing fails
func ParseRouteTarget(b []byte) (*RouteTarget, error) {
	if len(b) != 8 {
		return nil, fmt.Errorf("Route Target must be 8 bytes, got %d", len(b))
	}

	rt := &RouteTarget{}
	rt.Type = binary.BigEndian.Uint16(b[0:2])

	switch rt.Type {
	case 0x0002:
		// 2-octet AS Specific Extended Community
		// Bytes 2-3: 2-octet AS
		// Bytes 4-7: 4-octet assigned number
		rt.AS = uint32(binary.BigEndian.Uint16(b[2:4]))
		rt.AssignedNum = binary.BigEndian.Uint32(b[4:8])

	case 0x0102:
		// IPv4 Address Specific Extended Community
		// Bytes 2-5: IPv4 address
		// Bytes 6-7: 2-octet assigned number
		rt.IPv4 = fmt.Sprintf("%d.%d.%d.%d", b[2], b[3], b[4], b[5])
		rt.AssignedNum = uint32(binary.BigEndian.Uint16(b[6:8]))

	case 0x0202:
		// 4-octet AS Specific Extended Community
		// Bytes 2-5: 4-octet AS
		// Bytes 6-7: 2-octet assigned number
		rt.AS = binary.BigEndian.Uint32(b[2:6])
		rt.AssignedNum = uint32(binary.BigEndian.Uint16(b[6:8]))

	default:
		return nil, fmt.Errorf("unknown Route Target type: 0x%04x", rt.Type)
	}

	return rt, nil
}

// String returns a human-readable representation of the Route Target
func (rt *RouteTarget) String() string {
	switch rt.Type {
	case 0x0002:
		return fmt.Sprintf("RT:%d:%d", rt.AS, rt.AssignedNum)
	case 0x0102:
		return fmt.Sprintf("RT:%s:%d", rt.IPv4, rt.AssignedNum)
	case 0x0202:
		return fmt.Sprintf("RT:%d:%d", rt.AS, rt.AssignedNum)
	default:
		return fmt.Sprintf("RT:unknown-type-0x%04x", rt.Type)
	}
}
