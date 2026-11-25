package srv6

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"

	"github.com/sbezverk/gobmp/pkg/base"
)

const (
	// ISISLANEndXSIDType is the IS-IS LAN End.X SID TLV type (RFC 9514 §4.2).
	ISISLANEndXSIDType = 1107
	// OSPFv3LANEndXSIDType is the OSPFv3 LAN End.X SID TLV type (RFC 9514 §4.2).
	OSPFv3LANEndXSIDType = 1108
)

// LANEndXSIDTLV is a BGP-LS SRv6 LAN End.X SID with its LAN neighbor ID.
type LANEndXSIDTLV struct {
	EndXSIDTLV
	NeighborID string `json:"neighbor_id"`
}

// UnmarshalJSON restores the neighbor ID and the common End.X fields.
func (e *LANEndXSIDTLV) UnmarshalJSON(b []byte) error {
	var neighbor struct {
		ID string `json:"neighbor_id"`
	}
	if err := json.Unmarshal(b, &neighbor); err != nil {
		return err
	}
	var sid EndXSIDTLV
	if err := json.Unmarshal(b, &sid); err != nil {
		return err
	}
	*e = LANEndXSIDTLV{EndXSIDTLV: sid, NeighborID: neighbor.ID}
	return nil
}

// UnmarshalLANEndXSIDTLV decodes an IS-IS or OSPFv3 LAN End.X SID TLV value.
func UnmarshalLANEndXSIDTLV(b []byte, typ uint16, proto base.ProtoID) (*LANEndXSIDTLV, error) {
	const headerLen = 6
	var neighborLen int
	switch {
	case typ == ISISLANEndXSIDType && (proto == base.ISISL1 || proto == base.ISISL2):
		neighborLen = 6
	case typ == OSPFv3LANEndXSIDType && proto == base.OSPFv3:
		neighborLen = 4
	default:
		return nil, fmt.Errorf("LAN End.X SID TLV %d does not support Protocol-ID %d", typ, proto)
	}
	sidOffset := headerLen + neighborLen
	subTLVOffset := sidOffset + net.IPv6len
	if len(b) < subTLVOffset {
		return nil, fmt.Errorf("LAN End.X SID TLV %d: need at least %d bytes, have %d", typ, subTLVOffset, len(b))
	}
	if len(b) > math.MaxUint16 {
		return nil, fmt.Errorf("LAN End.X SID TLV %d: need at most %d bytes, have %d", typ, math.MaxUint16, len(b))
	}
	flags, err := UnmarshalEndXSIDFlags(b[2:3])
	if err != nil {
		return nil, err
	}
	subTLVs, err := unmarshalLANEndXSubTLVs(b[subTLVOffset:])
	if err != nil {
		return nil, err
	}
	result := &LANEndXSIDTLV{EndXSIDTLV: EndXSIDTLV{
		Type:             typ,
		Length:           uint16(len(b)),
		EndpointBehavior: binary.BigEndian.Uint16(b[:2]),
		Flags:            flags,
		Algorithm:        b[3],
		Weight:           b[4],
		SID:              netip.AddrFrom16([16]byte(b[sidOffset:subTLVOffset])).String(),
		SubTLVs:          subTLVs,
	}}
	neighbor := b[headerLen:sidOffset]
	if neighborLen == 6 {
		result.NeighborID = base.FormatISISNodeID(neighbor)
	} else {
		result.NeighborID = net.IP(neighbor).String()
	}
	return result, nil
}

func unmarshalLANEndXSubTLVs(b []byte) ([]SubTLV, error) {
	const headerLen = 4
	var result []SubTLV
	for len(b) > 0 {
		if len(b) < headerLen {
			return nil, fmt.Errorf("LAN End.X SID sub-TLV header: need %d bytes, have %d", headerLen, len(b))
		}
		typ := binary.BigEndian.Uint16(b[:2])
		if typ == 0 {
			return nil, fmt.Errorf("LAN End.X SID uses reserved sub-TLV type 0")
		}
		size := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b)-headerLen < size {
			return nil, fmt.Errorf("LAN End.X SID sub-TLV %d: need %d bytes, have %d", typ, size, len(b)-headerLen)
		}
		// RFC 9514 §8 fixes the SID Structure value length at four octets.
		if typ == 1252 && size != 4 {
			return nil, fmt.Errorf("LAN End.X SID Structure: need 4 bytes, have %d", size)
		}
		end := headerLen + size
		tlv, err := UnmarshalSRv6SubTLV(b[:end])
		if err != nil {
			return nil, err
		}
		if sid, ok := tlv.(*SIDStructure); ok {
			if total := int(sid.LBLength) + int(sid.LNLength) + int(sid.FunLength) + int(sid.ArgLength); total > 128 {
				return nil, fmt.Errorf("LAN End.X SID Structure length sum %d exceeds 128 bits", total)
			}
		}
		result = append(result, tlv)
		b = b[end:]
	}
	return result, nil
}
