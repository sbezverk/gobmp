package message

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// parseAFISAFIStat parses AFI/SAFI structured TLV (types 9, 10, 16, 17)
// Format: 2-byte AFI + 1-byte SAFI + 8-byte Gauge64
func parseAFISAFIStat(data []byte) (AFISAFIStat, error) {
	if len(data) < 11 {
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
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
		PeerType:   uint8(msg.PeerHeader.PeerType),
	}
	m.RemoteIP = msg.PeerHeader.GetPeerAddrString()
	m.RemoteBGPID = msg.PeerHeader.GetPeerBGPIDString()
	for _, tlv := range StatsMsg.StatsTLV {
		switch tlv.InformationType {
		case 0:
			m.PrefixesRejectedInbound = binary.BigEndian.Uint32(tlv.Information)
		case 1:
			m.DuplicatePrefixs = binary.BigEndian.Uint32(tlv.Information)
		case 2:
			m.DuplicateWithDraws = binary.BigEndian.Uint32(tlv.Information)
		case 3:
			m.InvalidatedDueCluster = binary.BigEndian.Uint32(tlv.Information)
		case 4:
			m.InvalidatedDueAspath = binary.BigEndian.Uint32(tlv.Information)
		case 5:
			m.InvalidatedDueOriginatorId = binary.BigEndian.Uint32(tlv.Information)
		case 6:
			m.InvalidatedAsConfed = binary.BigEndian.Uint32(tlv.Information)
		case 7:
			m.AdjRIBsIn = binary.BigEndian.Uint64(tlv.Information)
		case 8:
			m.LocalRib = binary.BigEndian.Uint64(tlv.Information)
		case 9:
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				glog.Warningf("failed to parse Type 9 (Per-AFI Adj-RIB-In): %v", err)
				continue
			}
			m.PerAFIAdjRIBsIn = append(m.PerAFIAdjRIBsIn, stat)
		case 10:
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				glog.Warningf("failed to parse Type 10 (Per-AFI Loc-RIB): %v", err)
				continue
			}
			m.PerAFILocRIB = append(m.PerAFILocRIB, stat)
		case 11:
			m.UpdatesAsWithdraw = binary.BigEndian.Uint32(tlv.Information)
		case 12:
			m.PrefixesAsWithdraw = binary.BigEndian.Uint32(tlv.Information)
		case 13:
			m.DuplicateUpdates = binary.BigEndian.Uint32(tlv.Information)
		case 14:
			m.PrePolicyAdjRIBOut = binary.BigEndian.Uint64(tlv.Information)
		case 15:
			m.PostPolicyAdjRIBOut = binary.BigEndian.Uint64(tlv.Information)
		case 16:
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				glog.Warningf("failed to parse Type 16 (Per-AFI Pre-policy): %v", err)
				continue
			}
			m.PerAFIPrePolicyAdjRIBOut = append(m.PerAFIPrePolicyAdjRIBOut, stat)
		case 17:
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				glog.Warningf("failed to parse Type 17 (Per-AFI Post-policy): %v", err)
				continue
			}
			m.PerAFIPostPolicyAdjRIBOut = append(m.PerAFIPostPolicyAdjRIBOut, stat)
		default:
			glog.Warningf("unprocessed stats type:%v", tlv.InformationType)
		}
	}
	if err := p.marshalAndPublish(&m, bmp.StatsReportMsg, []byte(m.RouterHash), false); err != nil {
		glog.Errorf("failed to process peer Stats Report message with error: %+v", err)
		return
	}
}
