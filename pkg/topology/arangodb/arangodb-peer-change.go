package arangodb

func (a *arangoDB) peerChangeHandler(obj *message.PeerStateChange) {
	glog.Infof("><SB> peer change handler - update db with peer change message data")

	// creates a new BGP peer document in Arango's BGPPeer vertex collection
	bgp_peer_document := &arangoDB.BGPPeer{
		RouterID:	message.LocalBGPID
		LocalIP:	message.LocalIP
		LocalASN:	message.LocalASN
		PeerIP:		message.RemoteIP
		PeerBGPID:	message.RemoteBGPID
		PeerASN:	message.RemoteASN
	}
	if err := a.Upsert(bgp_peer_document); err != nil {
		glog.Errorf("Encountered an error while upserting the bgp peer document", err)
	} else {
		glog.Errorf("Successfully added bgp peer document: %q with peer: %q\n", LocalBGPID, RemoteIP)
	}
}
