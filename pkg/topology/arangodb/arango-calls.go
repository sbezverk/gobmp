package arangodb

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/message"
	_ "github.com/sbezverk/gobmp/pkg/topology/database"
)

func (a *arangoDB) l3vpnHandler(obj *message.L3VPNPrefix) {
	//	db := a.GetArangoDBInterface()
	if obj == nil {
		glog.Warning("L3 VPN Prefix object is nil")
		return
	}

	glog.Infof("L3 VPN Prefix object: %v", *obj)
}
