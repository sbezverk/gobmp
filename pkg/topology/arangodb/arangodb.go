package arangodb

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/message"
	"github.com/sbezverk/gobmp/pkg/tools"
	"github.com/sbezverk/gobmp/pkg/topology/database"
	"github.com/sbezverk/gobmp/pkg/topology/dbclient"
)

var (
	arangoDBConnectTimeout = time.Duration(time.Second * 10)
)

type arangoDB struct {
	stop chan struct{}
	dbclient.DB
	*database.ArangoConn
}

// NewDBSrvClient returns an instance of a DB server client process
func NewDBSrvClient(arangoSrv, user, pass, dbname string) (dbclient.Srv, error) {
	if err := tools.URLAddrValidation(arangoSrv); err != nil {
		return nil, err
	}
	arangoConn, err := database.NewArango(database.ArangoConfig{
		URL:      arangoSrv,
		User:     user,
		Password: pass,
		Database: dbname,
	})
	if err != nil {
		return nil, err
	}
	arango := &arangoDB{
		stop: make(chan struct{}),
	}
	arango.DB = arango
	arango.ArangoConn = arangoConn

	return arango, nil
}

func (a *arangoDB) Start() error {
	glog.Infof("Connected to arango database, starting monitor")
	go a.monitor()

	return nil
}

func (a *arangoDB) Stop() error {
	close(a.stop)

	return nil
}

func (a *arangoDB) GetInterface() dbclient.DB {
	return a.DB
}

func (a *arangoDB) GetArangoDBInterface() *database.ArangoConn {
	return a.ArangoConn
}

func (a *arangoDB) StoreMessage(msgType int, msg interface{}) error {
	switch msgType {
	case bmp.PeerStateChangeMsg:
		p, ok := msg.(*message.PeerStateChange)
		if !ok {
			return fmt.Errorf("malformed PeerStateChange message")
		}
		// Remove after the corresponding handler is added
		glog.Infof("Object: %+v", p)
		// go a.peerChangeHandler(p)
	case bmp.UnicastPrefixMsg:
		un, ok := msg.(*message.UnicastPrefix)
		if !ok {
			return fmt.Errorf("malformed UnicastPrefix message")
		}
		// Remove after the corresponding handler is added
		glog.Infof("Object: %+v", un)
		// go a.unicastPrefixHandler(un)
	case bmp.LSNodeMsg:
		ln, ok := msg.(*message.LSNode)
		if !ok {
			return fmt.Errorf("malformed LSNode message")
		}
		// Remove after the corresponding handler is added
		glog.Infof("Object: %+v", ln)
		// go a.lsNodeHandler(ln)
	case bmp.LSLinkMsg:
		ll, ok := msg.(*message.LSLink)
		if !ok {
			return fmt.Errorf("malformed LSLink message")
		}
		// Remove after the corresponding handler is added
		glog.Infof("Object: %+v", ll)
		// go a.lsLinkHandler(ll)
	case bmp.L3VPNMsg:
		l3, ok := msg.(*message.L3VPNPrefix)
		if !ok {
			return fmt.Errorf("malformed L3VPN message")
		}
		// Remove after the corresponding handler is added
		glog.Infof("Object: %+v", l3)
		// go a.l3vpnHandler(l3)
	}

	return nil
}

func (a *arangoDB) monitor() {
	for {
		select {
		case <-a.stop:
			// TODO Add clean up of connection with Arango DB
			return
		}
	}
}
