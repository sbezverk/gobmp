package message

import (
	"encoding/binary"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

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
		glog.Errorf("stats message does not contain any tlv(stat) %+v", msg.Payload)
		return
	}

	m := Stats{
		RemoteASN:  msg.PeerHeader.PeerAS,
		PeerRD:     msg.PeerHeader.GetPeerDistinguisherString(),
		Timestamp:  msg.PeerHeader.GetPeerTimestamp(),
		RouterHash: p.speakerHash,
		RouterIP:   p.speakerIP,
	}

	if msg.PeerHeader.FlagV {
		m.RemoteIP = net.IP(msg.PeerHeader.PeerAddress).To16().String()
		m.RemoteBGPID = net.IP(msg.PeerHeader.PeerBGPID).To16().String()
	} else {
		m.RemoteIP = net.IP(msg.PeerHeader.PeerAddress[12:]).To4().String()
		m.RemoteBGPID = net.IP(msg.PeerHeader.PeerBGPID).To4().String()
	}

	for _, tlv := range StatsMsg.StatsTLV {
		switch tlv.InformationType {
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
		case 11:
			m.UpdatesAsWithdraw = binary.BigEndian.Uint32(tlv.Information)
		case 12:
			m.PrefixesAsWithdraw = binary.BigEndian.Uint32(tlv.Information)
		default:
			glog.Warningf("unprocessed stats type:%v", tlv.InformationType)
		}
	}
	if err := p.marshalAndPublish(&m, bmp.StatsReportMsg, []byte(m.RouterHash), false); err != nil {
		glog.Errorf("failed to process peer message with error: %+v", err)
		return
	}
}
