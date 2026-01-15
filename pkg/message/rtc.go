package message

import (
	"encoding/binary"
	"fmt"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// rtc processes MP_REACH_NLRI/MP_UNREACH_NLRI AFI 1/2 SAFI 132 (Route Target Constraint)
func (p *producer) rtc(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]*RTCPrefix, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	prfxs := make([]*RTCPrefix, 0)
	rtcRoute, err := nlri.GetNLRIRTC()
	if err != nil {
		return nil, err
	}

	// Handle EOR (End-of-RIB) when no NLRIs present
	if len(rtcRoute.NLRI) == 0 {
		return []*RTCPrefix{
			{
				Action:     operation,
				RouterHash: p.speakerHash,
				RouterIP:   p.speakerIP,
				PeerHash:   ph.GetPeerHash(),
				PeerASN:    ph.PeerAS,
				Timestamp:  ph.GetPeerTimestamp(),
				PeerType:   uint8(ph.PeerType),
				IsEOR:      true,
			},
		}, nil
	}

	for _, e := range rtcRoute.NLRI {
		prfx := &RTCPrefix{
			Action:         operation,
			RouterHash:     p.speakerHash,
			RouterIP:       p.speakerIP,
			PeerType:       uint8(ph.PeerType),
			PeerHash:       ph.GetPeerHash(),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.GetPeerTimestamp(),
			Length:         e.Length,
			OriginAS:       e.OriginAS,
			BaseAttributes: update.BaseAttributes,
		}

		// Set RIB flags
		if f, err := ph.IsAdjRIBInPost(); err == nil {
			prfx.IsAdjRIBInPost = f
		}
		if f, err := ph.IsAdjRIBOutPost(); err == nil {
			prfx.IsAdjRIBOutPost = f
		}
		if f, err := ph.IsAdjRIBOut(); err == nil {
			prfx.IsAdjRIBOut = f
		}
		if f, err := ph.IsLocRIB(); err == nil {
			prfx.IsLocRIB = f
		}
		if f, err := ph.IsLocRIBFiltered(); err == nil {
			prfx.IsLocRIBFiltered = f
		}
		// RFC 9069: Set TableName for LocRIB peers
		if prfx.IsLocRIB {
			prfx.TableName = p.GetTableName(ph.GetPeerBGPIDString(), ph.GetPeerDistinguisherString())
		}

		prfx.PeerIP = ph.GetPeerAddrString()
		prfx.IsIPv4 = !nlri.IsIPv6NLRI()

		// Format Route Target if present (length == 96 bits)
		if e.Length == 96 && len(e.RouteTarget) == 8 {
			prfx.RouteTarget = formatRouteTarget(e.RouteTarget)
		}

		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}

// formatRouteTarget formats the raw 8-byte Route Target Extended Community into a string
// Follows RFC 4360 format: Type:Value
func formatRouteTarget(rt []byte) string {
	if len(rt) != 8 {
		return fmt.Sprintf("0x%x", rt)
	}

	rtType := rt[0] & 0x3f

	switch rtType {
	case 0x00: // Two-Octet AS-Specific (Type 0)
		as := binary.BigEndian.Uint16(rt[2:4])
		val := binary.BigEndian.Uint32(rt[4:8])
		return fmt.Sprintf("%d:%d", as, val)

	case 0x01: // IPv4-Address-Specific (Type 1)
		ip := fmt.Sprintf("%d.%d.%d.%d", rt[2], rt[3], rt[4], rt[5])
		val := binary.BigEndian.Uint16(rt[6:8])
		return fmt.Sprintf("%s:%d", ip, val)

	case 0x02: // Four-Octet AS-Specific (Type 2)
		as := binary.BigEndian.Uint32(rt[2:6])
		val := binary.BigEndian.Uint16(rt[6:8])
		return fmt.Sprintf("%d:%d", as, val)

	default:
		return fmt.Sprintf("0x%x", rt)
	}
}
