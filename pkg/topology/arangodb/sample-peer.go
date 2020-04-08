package arangodb

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/message"
	"github.com/sbezverk/gobmp/pkg/topology/database"
)

func (a *arangoDB) samplePeerChangeHandler(obj *message.PeerStateChange) {
	db := a.GetArangoDBInterface()
	epenNodeDocument := &database.EPENode{
		RouterID: obj.LocalBGPID,
		PeerIP:   []string{obj.RemoteIP},
		ASN:      fmt.Sprintf("%d", obj.LocalASN),
	}
	if err := db.Upsert(epenNodeDocument); err != nil {
		glog.Errorf("Encountered an error while upserting the epe peer document %+v", err)
		return
	}
	glog.Infof("Successfully added epe peer document: %q with peer: %q\n", obj.LocalBGPID, obj.RemoteIP)
}
