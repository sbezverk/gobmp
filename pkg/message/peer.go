package message

import (
	"crypto/md5"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) producePeerMessage(op int, msg bmp.Message) {
	if msg.PeerHeader == nil {
		glog.Errorf("perPeerHeader is missing, cannot construct PeerStateChange message")
		return
	}
	peerUpMsg, ok := msg.Payload.(*bmp.PeerUpMessage)
	if !ok {
		glog.Errorf("got invalid Payload type in bmp.Message")
		return
	}
	action := "up"
	if op == peerDown {
		action = "down"
	}

	var m PeerStateChange

	if op == peerUP {
		m = PeerStateChange{
			Action:         action,
			RemoteASN:      msg.PeerHeader.PeerAS,
			PeerRD:         msg.PeerHeader.PeerDistinguisher.String(),
			RemotePort:     int(peerUpMsg.RemotePort),
			Timestamp:      msg.PeerHeader.PeerTimestamp,
			LocalPort:      int(peerUpMsg.LocalPort),
			AdvHolddown:    int(peerUpMsg.SentOpen.HoldTime),
			RemoteHolddown: int(peerUpMsg.ReceivedOpen.HoldTime),
		}
		if msg.PeerHeader.FlagV {
			m.IsIPv4 = false
			m.RemoteIP = net.IP(msg.PeerHeader.PeerAddress).To16().String()
			m.LocalIP = net.IP(peerUpMsg.LocalAddress).To16().String()
			m.RemoteBGPID = net.IP(msg.PeerHeader.PeerBGPID).To16().String()
			m.LocalBGPID = net.IP(peerUpMsg.SentOpen.BGPID).To16().String()
		} else {
			m.IsIPv4 = true
			m.RemoteIP = net.IP(msg.PeerHeader.PeerAddress[12:]).To4().String()
			m.LocalIP = net.IP(peerUpMsg.LocalAddress[12:]).To4().String()
			m.RemoteBGPID = net.IP(msg.PeerHeader.PeerBGPID).To4().String()
			m.LocalBGPID = net.IP(peerUpMsg.SentOpen.BGPID).To4().String()
		}
		// Saving local bgp speaker identities.
		p.speakerIP = m.LocalIP
		p.speakerHash = fmt.Sprintf("%x", md5.Sum([]byte(p.speakerIP)))
		m.RouterIP = p.speakerIP
		m.RouterHash = p.speakerHash

		m.LocalASN = int32(peerUpMsg.SentOpen.MyAS)
		if lasn, ok := peerUpMsg.SentOpen.Is4BytesASCapable(); ok {
			// Local BGP speaker is 4 bytes AS capable
			m.LocalASN = lasn
		}
		p.as4Capable = false
		_, l4as := peerUpMsg.SentOpen.Is4BytesASCapable()
		_, r4as := peerUpMsg.ReceivedOpen.Is4BytesASCapable()
		if l4as && r4as {
			// Both peers are AS 4 bytes capable
			p.as4Capable = true
		}
		sCaps := peerUpMsg.SentOpen.GetCapabilities()
		rCaps := peerUpMsg.ReceivedOpen.GetCapabilities()
		for i, cap := range sCaps {
			m.AdvCapabilities += cap.Description
			if i < len(sCaps)-1 {
				m.AdvCapabilities += ", "
			}
		}
		for i, cap := range rCaps {
			m.RcvCapabilities += cap.Description
			if i < len(rCaps)-1 {
				m.RcvCapabilities += ", "
			}
		}
	} else {
		peerDownMsg, ok := msg.Payload.(*bmp.PeerDownMessage)
		if !ok {
			glog.Errorf("got invalid Payload type in bmp.Message")
			return
		}
		m = PeerStateChange{
			Action:     "down",
			RouterIP:   p.speakerIP,
			RouterHash: p.speakerHash,
			BMPReason:  int(peerDownMsg.Reason),
			RemoteASN:  msg.PeerHeader.PeerAS,
			PeerRD:     msg.PeerHeader.PeerDistinguisher.String(),
			Timestamp:  msg.PeerHeader.PeerTimestamp,
		}
		if msg.PeerHeader.FlagV {
			m.IsIPv4 = false
			m.RemoteIP = net.IP(msg.PeerHeader.PeerAddress).To16().String()
			m.RemoteBGPID = net.IP(msg.PeerHeader.PeerBGPID).To16().String()
		} else {
			m.IsIPv4 = true
			m.RemoteIP = net.IP(msg.PeerHeader.PeerAddress[12:]).To4().String()
			m.RemoteBGPID = net.IP(msg.PeerHeader.PeerBGPID).To4().String()
		}
		m.InfoData = make([]byte, len(peerDownMsg.Data))
		copy(m.InfoData, peerDownMsg.Data)

	}
	if err := p.marshalAndPublish(&m, bmp.PeerStateChangeMsg, []byte(m.RouterHash), false); err != nil {
		glog.Errorf("failed to process Unicast Prefix message with error: %+v", err)
		return
	}
}
