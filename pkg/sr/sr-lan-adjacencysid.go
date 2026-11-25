package sr

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
)

// LANAdjacencySIDTLV is a BGP-LS LAN Adjacency SID (RFC 9085 §2.2.2).
type LANAdjacencySIDTLV struct {
	Flags      AdjacencySIDFlags `json:"flags,omitempty"`
	Weight     uint8             `json:"weight"`
	SID        uint32            `json:"sid"`
	NeighborID string            `json:"neighbor_id"`
}

// UnmarshalJSON restores the protocol-specific flag type.
func (a *LANAdjacencySIDTLV) UnmarshalJSON(b []byte) error {
	type fields LANAdjacencySIDTLV
	var value struct {
		fields
		Flags json.RawMessage `json:"flags"`
	}
	if err := json.Unmarshal(b, &value); err != nil {
		return err
	}
	if len(value.Flags) > 0 {
		flags, err := unmarshalAdjacencySIDFlagsJSON(value.Flags)
		if err != nil {
			return err
		}
		value.fields.Flags = flags
	}
	*a = LANAdjacencySIDTLV(value.fields)
	return nil
}

// UnmarshalLANAdjacencySIDTLV decodes TLV 1100 using the Link NLRI Protocol-ID.
func UnmarshalLANAdjacencySIDTLV(b []byte, proto base.ProtoID) (*LANAdjacencySIDTLV, error) {
	const headerLen = 4 // Flags, weight and two reserved octets.
	var neighborLen int
	var valueFlag, localFlag byte
	switch proto {
	case base.ISISL1, base.ISISL2:
		neighborLen, valueFlag, localFlag = 6, 0x20, 0x10
	case base.OSPFv2, base.OSPFv3:
		neighborLen, valueFlag, localFlag = 4, 0x40, 0x20
	default:
		return nil, fmt.Errorf("LAN Adjacency SID does not support Protocol-ID %d", proto)
	}
	sidOffset := headerLen + neighborLen
	if len(b) < sidOffset {
		return nil, fmt.Errorf("LAN Adjacency SID header: need %d bytes, have %d", sidOffset, len(b))
	}
	// RFC 8667 §2.2.2, RFC 8665 §6.2 and RFC 8666 §7.2 use a
	// local label when V and L are set and a global index when both are clear.
	v, l := b[0]&valueFlag != 0, b[0]&localFlag != 0
	if v != l {
		return nil, fmt.Errorf("LAN Adjacency SID has inconsistent V and L flags")
	}
	sidLen := 4
	if v {
		sidLen = 3
	}
	sid := b[sidOffset:]
	if len(sid) != sidLen {
		return nil, fmt.Errorf("LAN Adjacency SID value: need %d bytes, have %d", sidLen, len(sid))
	}
	flags, err := unmarshalAdjacencySIDFlags(b[:1], proto)
	if err != nil {
		return nil, err
	}
	neighbor := b[headerLen:sidOffset]
	result := &LANAdjacencySIDTLV{Flags: flags, Weight: b[1]}
	if neighborLen == 6 {
		result.NeighborID = base.FormatISISNodeID(neighbor)
	} else {
		result.NeighborID = net.IP(neighbor).String()
	}
	if v {
		// The MPLS label occupies the low 20 bits.
		result.SID = uint32(sid[0]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(sid[1:]))
	} else {
		result.SID = binary.BigEndian.Uint32(sid)
	}
	return result, nil
}
