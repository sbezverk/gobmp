package message

import (
	"crypto/md5"
	"encoding/hex"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) producePeerMessage(op int, msg bmp.Message) {
	if msg.PeerHeader == nil {
		glog.Errorf("perPeerHeader is missing, cannot construct PeerStateChange message")
		return
	}
	action := "add"
	if op == peerDown {
		action = "del"
	}

	var m PeerStateChange
	if op == peerUP {
		peerUpMsg, ok := msg.Payload.(*bmp.PeerUpMessage)
		if !ok {
			glog.Errorf("got invalid Payload type in bmp.Message %+v", msg.Payload)
			return
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
		m.RemoteIP = msg.PeerHeader.GetPeerAddrString()
		m.RemoteBGPID = msg.PeerHeader.GetPeerBGPIDString()
		m.LocalBGPID = net.IP(peerUpMsg.SentOpen.BGPID).To4().String()
		m.IsIPv4 = !msg.PeerHeader.IsRemotePeerIPv6()
		m.LocalIP = peerUpMsg.GetLocalAddressString()
		localSum := md5.Sum([]byte(m.LocalIP))
		m.LocalHash = hex.EncodeToString(localSum[:])
		m.RouterIP = m.LocalIP
		m.RouterHash = m.LocalHash
		m.TransportIP = p.transportIP
		m.TransportHash = p.transportHash
		m.LocalASN = uint32(peerUpMsg.SentOpen.MyAS)
		if lasn, ok := peerUpMsg.SentOpen.Is4BytesASCapable(); ok {
			// Local BGP speaker is 4 bytes AS capable
			m.LocalASN = lasn
		}

		// Create per-table properties for this VRF
		// Per RFC 9069: Each table identified by BGP-ID + Peer Distinguisher
		// Per RFC 7911: AddPath capability is per BGP session (not global)
		p.tableLock.Lock()
		ptp := PerTableProperties{
			addPathCapable: make(map[int]bool),
			localIP:        m.LocalIP,
			localHash:      m.LocalHash,
		}

		// Check AddPath capability for this specific peer/table
		// Only enable AddPath for AFI/SAFI types where BOTH peers support it
		if lAddPath := peerUpMsg.SentOpen.AddPathCapability(); len(lAddPath) != 0 {
			if rAddPath := peerUpMsg.ReceivedOpen.AddPathCapability(); len(rAddPath) != 0 {
				for k := range lAddPath {
					if capable, ok := rAddPath[k]; ok {
						ptp.addPathCapable[k] = capable
					}
				}
			}
		}

		// Copy table informational TLVs (includes Table Name per RFC 9069 Section 5)
		ptp.tableInfoTLVs = make([]bmp.InformationalTLV, len(peerUpMsg.Information))
		copy(ptp.tableInfoTLVs, peerUpMsg.Information)

		// Store properties for this table before signalling readiness, so that
		// RouteMonitor goroutines unblocked by markTableReady can immediately
		// call peerLocal() and find the entry.
		p.tableProperties[msg.PeerHeader.GetTableKey()] = ptp
		p.tableLock.Unlock()

		// Signal goroutines waiting for this specific table's PeerUp to complete.
		p.markTableReady(msg.PeerHeader.GetTableKey())

		m.AdvCapabilities = peerUpMsg.SentOpen.GetCapabilities()
		m.RcvCapabilities = peerUpMsg.ReceivedOpen.GetCapabilities()
		if glog.V(6) {
			glog.Infof("producer for transport ip: %s table: %s add path: %+v",
				p.transportIP,
				msg.PeerHeader.GetTableKey(),
				ptp.addPathCapable)
		}
	} else {
		peerDownMsg, ok := msg.Payload.(*bmp.PeerDownMessage)
		if !ok {
			glog.Errorf("got invalid Payload type in bmp.Message")
			return
		}
		// Fetch per-peer router identity before deleting table properties.
		routerIP, routerHash := p.peerLocal(msg.PeerHeader.GetTableKey())
		m = PeerStateChange{
			Action:        "down",
			RouterIP:      routerIP,
			RouterHash:    routerHash,
			TransportIP:   p.transportIP,
			TransportHash: p.transportHash,
			PeerType:      uint8(msg.PeerHeader.PeerType),
			BMPReason:     int(peerDownMsg.Reason),
			RemoteASN:     msg.PeerHeader.PeerAS,
			PeerRD:        msg.PeerHeader.GetPeerDistinguisherString(),
			Timestamp:     msg.PeerHeader.GetPeerTimestamp(),
		}
		m.RemoteIP = msg.PeerHeader.GetPeerAddrString()
		m.RemoteBGPID = msg.PeerHeader.GetPeerBGPIDString()
		m.IsIPv4 = !msg.PeerHeader.IsRemotePeerIPv6()
		m.InfoData = make([]byte, len(peerDownMsg.Data))
		copy(m.InfoData, peerDownMsg.Data)

		// Reset the per-table ready channel before deleting properties so the
		// next session's goroutines wait for the new PeerUp.
		p.resetTableReady(msg.PeerHeader.GetTableKey())
		// Clean up table properties when peer goes down
		// This prevents memory leaks and ensures stale data isn't used
		p.tableLock.Lock()
		delete(p.tableProperties, msg.PeerHeader.GetTableKey())
		p.tableLock.Unlock()
	}
	if err := p.marshalAndPublish(&m, bmp.PeerStateChangeMsg, []byte(m.RouterHash)); err != nil {
		glog.Errorf("failed to process peer message with error: %+v", err)
		return
	}
}
