package message

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// parseAFISAFIStat parses AFI/SAFI structured TLV (types 9, 10, 16, 17; RFC 9972 types 19, 21-23, 26-28, 30, 32, 34-38, 40-43)
// Format: 2-byte AFI + 1-byte SAFI + 8-byte Gauge64 (RFC 7854 Section 4.8, RFC 8671 Section 6.2, RFC 9972 Section 3.1)
// RFC 9972 Section 3.1 requires Stat Len 11 for its per-AFI/SAFI types; types 9,
// 10, 16 and 17 have the same 11-byte structure, so any other length is rejected.
func parseAFISAFIStat(data []byte) (AFISAFIStat, error) {
	if len(data) != 11 {
		return AFISAFIStat{}, fmt.Errorf("invalid AFI/SAFI stat length: %d, expected 11", len(data))
	}

	return AFISAFIStat{
		AFI:   binary.BigEndian.Uint16(data[0:2]),
		SAFI:  data[2],
		Count: binary.BigEndian.Uint64(data[3:11]),
	}, nil
}

// produceStatsMessage proceduces message from BMP Statistic Message
func (p *producer) produceStatsMessage(msg bmp.Message) {
	if msg.PeerHeader == nil {
		glog.Errorf("perPeerHeader is missing, cannot construct Stats message")
		return
	}
	StatsMsg, ok := msg.Payload.(*bmp.StatsReport)
	if !ok {
		glog.Errorf("got invalid Payload type in bmp.StatsReport %+v", msg.Payload)
		return
	}
	if len(StatsMsg.StatsTLV) == 0 {
		b, _ := json.MarshalIndent(StatsMsg, "", "   ")
		glog.Errorf("stats message does not contain any tlv(stat) %s", string(b))
		return
	}

	m := Stats{
		RemoteASN:  msg.PeerHeader.PeerAS,
		PeerRD:     msg.PeerHeader.GetPeerDistinguisherString(),
		Timestamp:  msg.PeerHeader.GetPeerTimestamp(),
		RouterHash: msg.PeerHeader.Identity.RouterHash,
		RouterIP:   msg.PeerHeader.Identity.RouterIP,
		PeerType:   uint8(msg.PeerHeader.PeerType),
	}
	m.RemoteIP = msg.PeerHeader.GetPeerAddrString()
	m.RemoteBGPID = msg.PeerHeader.GetPeerBGPIDString()
	for _, tlv := range StatsMsg.StatsTLV {
		switch tlv.InformationType {
		case 0, 1, 2, 3, 4, 5, 6, 11, 12, 13:
			if len(tlv.Information) < 4 {
				glog.Warningf("stats type %d from peer %s (router %s): need 4 bytes, got %d", tlv.InformationType, m.RemoteIP, m.RouterIP, len(tlv.Information))
				continue
			}
			v := binary.BigEndian.Uint32(tlv.Information)
			switch tlv.InformationType {
			case 0:
				m.PrefixesRejectedInbound = v
			case 1:
				m.DuplicatePrefixs = v
			case 2:
				m.DuplicateWithDraws = v
			case 3:
				m.InvalidatedDueCluster = v
			case 4:
				m.InvalidatedDueAspath = v
			case 5:
				m.InvalidatedDueOriginatorId = v
			case 6:
				m.InvalidatedAsConfed = v
			case 11:
				m.UpdatesAsWithdraw = v
			case 12:
				m.PrefixesAsWithdraw = v
			case 13:
				m.DuplicateUpdates = v
			}
		case 7, 8, 14, 15:
			if len(tlv.Information) < 8 {
				glog.Warningf("stats type %d from peer %s (router %s): need 8 bytes, got %d", tlv.InformationType, m.RemoteIP, m.RouterIP, len(tlv.Information))
				continue
			}
			v := binary.BigEndian.Uint64(tlv.Information)
			switch tlv.InformationType {
			case 7:
				m.AdjRIBsIn = v
			case 8:
				m.LocalRib = v
			case 14:
				m.PrePolicyAdjRIBOut = v
			case 15:
				m.PostPolicyAdjRIBOut = v
			}
		case 9:
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				glog.Warningf("failed to parse Type 9 (Per-AFI Adj-RIB-In) from peer %s (router %s): %v", m.RemoteIP, m.RouterIP, err)
				continue
			}
			m.PerAFIAdjRIBsIn = append(m.PerAFIAdjRIBsIn, stat)
		case 10:
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				glog.Warningf("failed to parse Type 10 (Per-AFI Loc-RIB) from peer %s (router %s): %v", m.RemoteIP, m.RouterIP, err)
				continue
			}
			m.PerAFILocRIB = append(m.PerAFILocRIB, stat)
		case 16:
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				glog.Warningf("failed to parse Type 16 (Per-AFI Pre-policy) from peer %s (router %s): %v", m.RemoteIP, m.RouterIP, err)
				continue
			}
			m.PerAFIPrePolicyAdjRIBOut = append(m.PerAFIPrePolicyAdjRIBOut, stat)
		case 17:
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				glog.Warningf("failed to parse Type 17 (Per-AFI Post-policy) from peer %s (router %s): %v", m.RemoteIP, m.RouterIP, err)
				continue
			}
			m.PerAFIPostPolicyAdjRIBOut = append(m.PerAFIPostPolicyAdjRIBOut, stat)
		case 18, 20, 29, 31, 33, 39:
			// RFC 9972 Section 3.1: Stat Len MUST be 8 for global statistics.
			if len(tlv.Information) != 8 {
				glog.Warningf("RFC 9972 stats type %d from peer %s (router %s): need exactly 8 bytes, got %d", tlv.InformationType, m.RemoteIP, m.RouterIP, len(tlv.Information))
				continue
			}
			v := binary.BigEndian.Uint64(tlv.Information)
			switch tlv.InformationType {
			case 18:
				m.PrePolicyAdjRIBIn = v
			case 20:
				m.PostPolicyAdjRIBIn = v
			case 29:
				m.PostPolicyAdjRIBInThresholdLeft = v
			case 31:
				m.LicenseThresholdLeft = v
			case 33:
				m.PrePolicyAdjRIBInASPathTooLong = v
			case 39:
				m.PrePolicyAdjRIBOutASPathTooLong = v
			}
		case 19, 21, 22, 23, 26, 27, 28, 30, 32, 34, 35, 36, 37, 38, 40, 41, 42, 43:
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				glog.Warningf("failed to parse RFC 9972 type %d from peer %s (router %s): %v", tlv.InformationType, m.RemoteIP, m.RouterIP, err)
				continue
			}
			switch tlv.InformationType {
			case 19:
				m.PerAFIPrePolicyAdjRIBIn = append(m.PerAFIPrePolicyAdjRIBIn, stat)
			case 21:
				m.PerAFIPostPolicyAdjRIBIn = append(m.PerAFIPostPolicyAdjRIBIn, stat)
			case 22:
				m.PerAFIPrePolicyAdjRIBInRejected = append(m.PerAFIPrePolicyAdjRIBInRejected, stat)
			case 23:
				m.PerAFIPostPolicyAdjRIBInAccepted = append(m.PerAFIPostPolicyAdjRIBInAccepted, stat)
			case 26:
				m.PerAFIRouteDampingSuppressed = append(m.PerAFIRouteDampingSuppressed, stat)
			case 27:
				m.PerAFIGRStale = append(m.PerAFIGRStale, stat)
			case 28:
				m.PerAFILLGRStale = append(m.PerAFILLGRStale, stat)
			case 30:
				m.PerAFIPostPolicyAdjRIBInThresholdLeft = append(m.PerAFIPostPolicyAdjRIBInThresholdLeft, stat)
			case 32:
				m.PerAFILicenseThresholdLeft = append(m.PerAFILicenseThresholdLeft, stat)
			case 34:
				m.PerAFIPrePolicyAdjRIBInASPathTooLong = append(m.PerAFIPrePolicyAdjRIBInASPathTooLong, stat)
			case 35:
				m.PerAFIPostPolicyAdjRIBInRPKIInvalid = append(m.PerAFIPostPolicyAdjRIBInRPKIInvalid, stat)
			case 36:
				m.PerAFIPostPolicyAdjRIBInRPKIValid = append(m.PerAFIPostPolicyAdjRIBInRPKIValid, stat)
			case 37:
				m.PerAFIPostPolicyAdjRIBInRPKINotFound = append(m.PerAFIPostPolicyAdjRIBInRPKINotFound, stat)
			case 38:
				m.PerAFIPrePolicyAdjRIBOutRejected = append(m.PerAFIPrePolicyAdjRIBOutRejected, stat)
			case 40:
				m.PerAFIPrePolicyAdjRIBOutASPathTooLong = append(m.PerAFIPrePolicyAdjRIBOutASPathTooLong, stat)
			case 41:
				m.PerAFIPostPolicyAdjRIBOutRPKIInvalid = append(m.PerAFIPostPolicyAdjRIBOutRPKIInvalid, stat)
			case 42:
				m.PerAFIPostPolicyAdjRIBOutRPKIValid = append(m.PerAFIPostPolicyAdjRIBOutRPKIValid, stat)
			case 43:
				m.PerAFIPostPolicyAdjRIBOutRPKINotFound = append(m.PerAFIPostPolicyAdjRIBOutRPKINotFound, stat)
			}
		default:
			glog.Warningf("unprocessed stats type:%v", tlv.InformationType)
		}
	}
	if err := p.marshalAndPublish(&m, bmp.StatsReportMsg, []byte(m.RouterHash)); err != nil {
		glog.Errorf("failed to process peer Stats Report message with error: %+v", err)
		return
	}
}
