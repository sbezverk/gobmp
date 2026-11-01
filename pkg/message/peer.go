package message

import (
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) producePeerMessage(op int, msg bmp.Message, peerID bmp.PeerIdentity) (*PeerStateChange, error) {
	if msg.PeerHeader == nil {
		return nil, fmt.Errorf("perPeerHeader is missing, cannot construct PeerStateChange message")
	}
	action := "add"
	if op == peerDown {
		action = "del"
	}
	var m PeerStateChange
	if op == peerUP {
		peerUpMsg, ok := msg.Payload.(*bmp.PeerUpMessage)
		if !ok {
			return nil, fmt.Errorf("got invalid Payload type in bmp.Message %+v", msg.Payload)
		}
		m = PeerStateChange{
			Action:         action,
			RemoteASN:      msg.PeerHeader.PeerAS,
			PeerType:       uint8(msg.PeerHeader.PeerType),
			PeerRD:         msg.PeerHeader.GetPeerDistinguisherString(),
			RemotePort:     int(peerUpMsg.RemotePort),
			Timestamp:      msg.PeerHeader.GetPeerTimestamp(),
			LocalPort:      int(peerUpMsg.LocalPort),
			AdvHolddown:    int(peerUpMsg.SentOpen.HoldTime),
			RemoteHolddown: int(peerUpMsg.ReceivedOpen.HoldTime),
		}
		if f, err := msg.PeerHeader.IsAdjRIBInPost(); err == nil {
			m.IsAdjRIBInPost = f
		}
		if f, err := msg.PeerHeader.IsAdjRIBOutPost(); err == nil {
			m.IsAdjRIBOutPost = f
		}
		if f, err := msg.PeerHeader.IsAdjRIBOut(); err == nil {
			m.IsAdjRIBOut = f
		}
		if f, err := msg.PeerHeader.IsLocRIB(); err == nil {
			m.IsLocRIB = f
		}
		if f, err := msg.PeerHeader.IsLocRIBFiltered(); err == nil {
			m.IsLocRIBFiltered = f
		}

		m.RouterIP = peerID.RouterIP
		m.RouterHash = peerID.RouterHash
		m.RemoteIP = peerID.PeerIP

		m.RemoteBGPID = msg.PeerHeader.GetPeerBGPIDString()
		m.LocalBGPID = net.IP(peerUpMsg.SentOpen.BGPID).To4().String()
		m.IsIPv4 = !msg.PeerHeader.IsRemotePeerIPv6()
		m.LocalIP = peerUpMsg.GetLocalAddressString()

		m.LocalASN = uint32(peerUpMsg.SentOpen.MyAS)
		if lasn, ok := peerUpMsg.SentOpen.Is4BytesASCapable(); ok {
			// Local BGP speaker is 4 bytes AS capable
			m.LocalASN = lasn
		}

		addPath := p.setPeerProperties(msg.PeerHeader, peerUpMsg)
		p.speakerReadyOnce.Do(func() {
			close(p.speakerReady)
		})

		m.AdvCapabilities = peerUpMsg.SentOpen.GetCapabilities()
		m.RcvCapabilities = peerUpMsg.ReceivedOpen.GetCapabilities()
		if glog.V(6) {
			glog.Infof("producer for speaker ip: %s peer: %s add path in: %+v out: %+v",
				peerID.SpeakerIP,
				msg.PeerHeader.PeerIdentity(),
				addPath.in, addPath.out)
		}
	} else {
		peerDownMsg, ok := msg.Payload.(*bmp.PeerDownMessage)
		if !ok {
			return nil, fmt.Errorf("got invalid Payload type in bmp.Message")
		}
		m = PeerStateChange{
			Action:    "down",
			PeerType:  uint8(msg.PeerHeader.PeerType),
			BMPReason: int(peerDownMsg.Reason),
			RemoteASN: msg.PeerHeader.PeerAS,
			PeerRD:    msg.PeerHeader.GetPeerDistinguisherString(),
			Timestamp: msg.PeerHeader.GetPeerTimestamp(),
		}
		m.RouterIP = peerID.RouterIP
		m.RouterHash = peerID.RouterHash
		m.RemoteIP = peerID.PeerIP
		m.RemoteBGPID = msg.PeerHeader.GetPeerBGPIDString()
		m.IsIPv4 = !msg.PeerHeader.IsRemotePeerIPv6()
		m.InfoData = make([]byte, len(peerDownMsg.Data))
		copy(m.InfoData, peerDownMsg.Data)

		p.tableLock.Lock()
		delete(p.peerAddPath, msg.PeerHeader.PeerIdentity())
		if msg.PeerHeader.PeerType == bmp.PeerType3 {
			delete(p.tableProperties, msg.PeerHeader.GetTableKey())
		}
		p.tableLock.Unlock()
	}

	return &m, nil
}

// speakerAddress picks the address that identifies the BMP speaker for this
// connection.  The Peer Up Local Address is preferred, so the identity of an
// established session is unchanged, but it is not always an address: RFC 9069
// Section 5.2 has a Loc-RIB Instance Peer zero-fill it, and a speaker whose
// first Peer Up describes the Loc-RIB therefore latches on 0.0.0.0 (or :: for
// an IPv6 peer).  Every such speaker then hashes to md5("0.0.0.0") and two of
// them become indistinguishable to a collector that keys on router_hash.
//
// connIP is the remote address of the TCP connection the message arrived on,
// which the server already resolves per client.  It identifies the speaker
// whenever the Peer Up does not, and it cannot collide between two connections.
func speakerAddress(localIP, connIP string) string {
	if isSpecificAddress(localIP) {
		return localIP
	}
	if isSpecificAddress(connIP) {
		return connIP
	}
	// Neither identifies anything.  Keep the Peer Up value rather than invent
	// one, leaving the message exactly as it was before this fallback existed.
	return localIP
}

// isSpecificAddress reports whether s is an IP address that names one host,
// as opposed to being absent or the unspecified address 0.0.0.0 / ::.
func isSpecificAddress(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsUnspecified()
}
