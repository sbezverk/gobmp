package arangodb

func (m *arangoDB) peerChangeHandler(obj *message.PeerStateChange) {
	glog.Infof("><SB> peer change handler - update db with peer change message data")

	// creates a new BGP peer document in Arango's BGPPeer test collection
	bgp_peer_document := &arangoDB.BGPPeer{
		RouterID:	message.LocalBGPID
		LocalIP:	message.LocalIP
		LocalASN:	message.LocalASN
		PeerIP:		message.RemoteIP
		PeerBGPID:	message.RemoteBGPID
		PeerASN:	message.RemoteASN
	}
	if err := m.arangoDB.Upsert(bgp_peer_document); err != nil {
		fmt.Println("Encountered an error while upserting the bgp peer document", err)
	} else {
		fmt.Printf("Successfully added bgp peer document: %q with peer: %q\n", LocalBGPID, RemoteIP)
	}
}
