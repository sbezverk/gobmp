package arangodb

import (
	"time"

	"github.com/golang/glog"
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
	dbi database.ArangoConn
}

// NewDBSrvClient returns an instance of a DB server client process
func NewDBSrvClient(arangoSrv, user, pass, dbname string) (dbclient.Srv, error) {
	if err := tools.URLAddrValidation(arangoSrv); err != nil {
		return nil, err
	}
	dbi, err := database.NewArango(database.ArangoConfig{
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
		dbi:  dbi,
	}
	arango.DB = arango

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
	return &arangoDB{}
}

func (a *arangoDB) StoreMessage(msgType int, msg interface{}) error {
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
