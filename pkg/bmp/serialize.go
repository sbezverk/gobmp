package bmp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

// SetFlags sets the wire flags for the current PeerType. For peer types 0–2,
// bits 7–4 are V,L,A,O; for Loc-RIB (type 3), only bit 7 (F) is defined.
// Reserved bits are rejected. A=1 means two-byte AS_PATH encoding.
func (p *PerPeerHeader) SetFlags(flags byte) error {
	if p == nil || p.PeerType > PeerType3 {
		return fmt.Errorf("invalid BMP peer type")
	}
	mask := byte(0xf0)
	if p.PeerType == PeerType3 {
		mask = 0x80
	}
	if flags & ^mask != 0 {
		return fmt.Errorf("reserved BMP per-peer flags %#x", flags)
	}
	p.flagF, p.flagV, p.flagL, p.flagA, p.flagO = false, false, false, false, false
	if p.PeerType == PeerType3 {
		p.flagF = flags&0x80 != 0
	} else {
		p.flagV, p.flagL, p.flagA, p.flagO = flags&0x80 != 0, flags&0x40 != 0, flags&0x20 != 0, flags&0x10 != 0
	}
	return nil
}

// Serialize returns the 42-byte BMP per-peer header. Slice fields must contain
// their full wire widths (8-byte distinguisher, 16-byte address, 4-byte BGP ID,
// 8-byte timestamp). No caller-owned data is modified or retained.
func (p *PerPeerHeader) Serialize() ([]byte, error) {
	if p == nil || p.PeerType > PeerType3 {
		return nil, fmt.Errorf("invalid BMP per-peer header")
	}
	if len(p.PeerDistinguisher) != 8 || len(p.PeerAddress) != 16 || len(p.PeerBGPID) != 4 || len(p.PeerTimestamp) != 8 {
		return nil, fmt.Errorf("invalid BMP per-peer field width")
	}
	if binary.BigEndian.Uint32(p.PeerTimestamp[4:]) >= 1000000 {
		return nil, fmt.Errorf("BMP timestamp microseconds must be less than 1000000")
	}
	flags := byte(0)
	if p.PeerType == PeerType3 {
		if p.flagV || p.flagL || p.flagA || p.flagO || !bytes.Equal(p.PeerAddress, make([]byte, 16)) {
			return nil, fmt.Errorf("invalid Loc-RIB address or flags")
		}
		if p.flagF {
			flags = 0x80
		}
	} else {
		if p.flagF {
			return nil, fmt.Errorf("flag F is only valid for Loc-RIB")
		}
		if !p.flagV && !bytes.Equal(p.PeerAddress[:12], make([]byte, 12)) {
			return nil, fmt.Errorf("IPv4 peer address has nonzero padding")
		}
		if p.flagV {
			flags |= 0x80
		}
		if p.flagL {
			flags |= 0x40
		}
		if p.flagA {
			flags |= 0x20
		}
		if p.flagO {
			flags |= 0x10
		}
	}
	b := []byte{byte(p.PeerType), flags}
	b = append(b, p.PeerDistinguisher...)
	b = append(b, p.PeerAddress...)
	b = binary.BigEndian.AppendUint32(b, p.PeerAS)
	b = append(b, p.PeerBGPID...)
	return append(b, p.PeerTimestamp...), nil
}

// Serialize returns an informational TLV, deriving InformationLength from its
// value. Unknown types are retained; values exceeding uint16 are rejected.
func (t InformationalTLV) Serialize() ([]byte, error) {
	if len(t.Information) > math.MaxUint16 {
		return nil, fmt.Errorf("BMP TLV %d exceeds uint16 length", t.InformationType)
	}
	b := binary.BigEndian.AppendUint16(nil, t.InformationType)
	b = binary.BigEndian.AppendUint16(b, uint16(len(t.Information)))
	return append(b, t.Information...), nil
}

func serializeTLVs(tlvs []InformationalTLV) ([]byte, error) {
	var b []byte
	for _, tlv := range tlvs {
		v, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		b = append(b, v...)
	}
	return b, nil
}

// Serialize returns an Initiation body. RFC 7854 section 4.3 requires both
// sysDescr (type 1) and sysName (type 2); additional TLVs retain their order.
func (p *InitiationMessage) Serialize() ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("nil BMP Initiation")
	}
	var sysDescr, sysName bool
	for _, tlv := range p.TLV {
		sysDescr = sysDescr || tlv.InformationType == 1
		sysName = sysName || tlv.InformationType == 2
	}
	if !sysDescr || !sysName {
		return nil, fmt.Errorf("BMP Initiation requires sysDescr and sysName TLVs")
	}
	return serializeTLVs(p.TLV)
}

// Serialize returns a Statistics Report body. StatsCount is derived from StatsTLV.
func (p *StatsReport) Serialize() ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("nil BMP Statistics Report")
	}
	if uint64(len(p.StatsTLV)) > math.MaxUint32 {
		return nil, fmt.Errorf("too many BMP statistics")
	}
	for _, tlv := range p.StatsTLV {
		width := 0
		switch tlv.InformationType {
		case 0, 1, 2, 3, 4, 5, 6, 11, 12, 13:
			width = 4
		case 7, 8, 14, 15:
			width = 8
		case 9, 10, 16, 17:
			width = 11
		}
		if width != 0 && len(tlv.Information) != width {
			return nil, fmt.Errorf("BMP statistic %d requires %d bytes", tlv.InformationType, width)
		}
	}
	b, err := serializeTLVs(p.StatsTLV)
	if err != nil {
		return nil, err
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(p.StatsTLV))), b...), nil
}

// Serialize returns a Termination body, with String TLVs followed by the
// required Reason TLV. Unknown TLVs and original ordering are not retained by
// the existing parsed structure, so byte-identical round trips are not promised.
func (p *TerminationMessage) Serialize() ([]byte, error) {
	if p == nil || !p.HasReason {
		return nil, fmt.Errorf("BMP Termination requires a Reason")
	}
	tlvs := make([]InformationalTLV, 0, len(p.Strings)+1)
	for _, s := range p.Strings {
		tlvs = append(tlvs, InformationalTLV{InformationType: 0, Information: []byte(s)})
	}
	tlvs = append(tlvs, InformationalTLV{InformationType: 1, Information: binary.BigEndian.AppendUint16(nil, p.Reason)})
	return serializeTLVs(tlvs)
}

// Serialize returns a Peer Down body. Known reasons require their specified
// notification/FSM payload, while unknown nonzero reasons retain opaque Data.
func (p *PeerDownMessage) Serialize() ([]byte, error) {
	if p == nil || p.Reason == 0 {
		return nil, fmt.Errorf("invalid BMP Peer Down reason")
	}
	switch p.Reason {
	case 1, 3:
		if len(p.Data) < 21 || len(p.Data) > 4096 || !bytes.Equal(p.Data[:16], bytes.Repeat([]byte{255}, 16)) || int(binary.BigEndian.Uint16(p.Data[16:18])) != len(p.Data) || p.Data[18] != 3 {
			return nil, fmt.Errorf("peer down requires a complete BGP NOTIFICATION")
		}
	case 2:
		if len(p.Data) != 2 {
			return nil, fmt.Errorf("peer down reason 2 requires a two-byte FSM event")
		}
	case 6:
		if _, err := UnmarshalTLV(p.Data); err != nil {
			return nil, fmt.Errorf("invalid Loc-RIB Peer Down TLVs: %w", err)
		}
	case 4, 5:
		if len(p.Data) != 0 {
			return nil, fmt.Errorf("peer down reason %d must not carry data", p.Reason)
		}
	}
	return append([]byte{p.Reason}, p.Data...), nil
}

// Serialize returns a Route Monitoring body containing a complete BGP UPDATE.
// Its raw UPDATE attributes/NLRI must already use the session's wire encoding.
// RFC 8671 section 5.2 placeholders are preserved; only the complete Message
// can check their compatibility with the RIB view.
func (p *RouteMonitor) Serialize() ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("nil BMP Route Monitoring")
	}
	return p.Update.Serialize()
}

// Serialize returns a Peer Up body with two complete BGP OPENs. LocalAddress
// must contain its 16-byte wire representation; the complete Message validates
// its family against the accompanying per-peer header.
func (p *PeerUpMessage) Serialize() ([]byte, error) {
	if p == nil || len(p.LocalAddress) != 16 {
		return nil, fmt.Errorf("invalid BMP Peer Up local address")
	}
	sent, err := p.SentOpen.Serialize()
	if err != nil {
		return nil, fmt.Errorf("sent OPEN: %w", err)
	}
	recv, err := p.ReceivedOpen.Serialize()
	if err != nil {
		return nil, fmt.Errorf("received OPEN: %w", err)
	}
	info, err := serializeTLVs(p.Information)
	if err != nil {
		return nil, err
	}
	b := append([]byte(nil), p.LocalAddress...)
	b = binary.BigEndian.AppendUint16(b, p.LocalPort)
	b = binary.BigEndian.AppendUint16(b, p.RemotePort)
	b = append(b, sent...)
	b = append(b, recv...)
	return append(b, info...), nil
}

// Serialize returns a complete BMP v3 frame for one of the six represented
// typed payloads. Its type and all lengths/counts are derived from the payload;
// SpeakerIP and Identity are collector metadata and are not encoded. RAW and
// Route Mirroring are unsupported. The result owns its bytes. Serializing
// normalized parsed structures guarantees semantic, not byte-identical, output.
func (m *Message) Serialize() ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("nil BMP Message")
	}
	var kind byte
	var body []byte
	var err error
	switch p := m.Payload.(type) {
	case *RouteMonitor:
		kind = RouteMonitorMsg
		body, err = p.Serialize()
	case *StatsReport:
		kind = StatsReportMsg
		body, err = p.Serialize()
	case *PeerDownMessage:
		kind = PeerDownMsg
		body, err = p.Serialize()
	case *PeerUpMessage:
		kind = PeerUpMsg
		body, err = p.Serialize()
	case *InitiationMessage:
		kind = InitiationMsg
		body, err = p.Serialize()
	case *TerminationMessage:
		kind = TerminationMsg
		body, err = p.Serialize()
	default:
		return nil, fmt.Errorf("unsupported BMP payload %T", m.Payload)
	}
	if err != nil {
		return nil, err
	}
	var peer []byte
	if kind == InitiationMsg || kind == TerminationMsg {
		if m.PeerHeader != nil {
			return nil, fmt.Errorf("BMP message type %d must not have a per-peer header", kind)
		}
	} else {
		peer, err = m.PeerHeader.Serialize()
		if err != nil {
			return nil, err
		}
		if p, ok := m.Payload.(*PeerUpMessage); ok {
			if !m.PeerHeader.IsRemotePeerIPv6() && !bytes.Equal(p.LocalAddress[:12], make([]byte, 12)) {
				return nil, fmt.Errorf("IPv4 Peer Up local address has nonzero padding")
			}
			if m.PeerHeader.PeerType == PeerType3 {
				// RFC 9069 section 5.2 requires zero local address/ports and
				// the same fabricated OPEN, including AS4, in both positions.
				sent, _ := p.SentOpen.Serialize()
				recv, _ := p.ReceivedOpen.Serialize()
				if !bytes.Equal(p.LocalAddress, make([]byte, 16)) || p.LocalPort != 0 || p.RemotePort != 0 || !bytes.Equal(sent, recv) || !openHasAS4(sent) {
					return nil, fmt.Errorf("invalid Loc-RIB Peer Up address, ports or OPEN capabilities")
				}
			}
		}
		if p, ok := m.Payload.(*PeerDownMessage); ok {
			// RFC 9069 section 5.3: Loc-RIB Peer Down MUST use reason 6.
			if m.PeerHeader.PeerType == PeerType3 && p.Reason != 6 {
				return nil, fmt.Errorf("Loc-RIB Peer Down requires reason 6")
			}
		}
		if kind == RouteMonitorMsg {
			// RFC 8671 section 5.2 permits zero-length mandatory attributes
			// in pre-policy Adj-RIB-Out. Keep the raw bytes, rejecting these
			// placeholders when the complete frame identifies another view.
			outPre, _ := m.PeerHeader.IsAdjRIBOutPre()
			for _, attr := range m.Payload.(*RouteMonitor).Update.PathAttributes {
				if len(attr.Attribute) == 0 && (attr.AttributeType == 1 || attr.AttributeType == 3 || attr.AttributeType == 5) && !outPre {
					return nil, fmt.Errorf("zero-length attribute %d requires pre-policy Adj-RIB-Out", attr.AttributeType)
				}
			}
			as4 := true // RFC 9069 section 5.4.1 requires AS4 for Loc-RIB.
			if m.PeerHeader.PeerType != PeerType3 {
				as4, _ = m.PeerHeader.Is4ByteASN()
			}
			if _, err = UnmarshalBMPRouteMonitorMessageWithAS4Hint(body, as4); err != nil {
				return nil, fmt.Errorf("UPDATE incompatible with per-peer header: %w", err)
			}
		}
	}
	total := uint64(CommonHeaderLength) + uint64(len(peer)) + uint64(len(body))
	if total > math.MaxUint32 {
		return nil, fmt.Errorf("BMP frame exceeds uint32 length")
	}
	b := []byte{3}
	b = binary.BigEndian.AppendUint32(b, uint32(total))
	b = append(b, kind)
	b = append(b, peer...)
	return append(b, body...), nil
}

// The OPEN serializer has already validated its framing. Parsing here also
// handles callers supplying raw type-2 optional parameters instead of the map.
func openHasAS4(frame []byte) bool {
	o, err := bgp.UnmarshalBGPOpenMessage(frame[16:])
	if err != nil {
		return false
	}
	for _, c := range o.Capabilities[65] {
		if c != nil && len(c.Value) == 4 {
			return true
		}
	}
	return false
}
