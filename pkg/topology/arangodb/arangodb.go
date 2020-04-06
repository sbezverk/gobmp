package arangodb

import (
	"context"
	"time"

	driver "github.com/arangodb/go-driver"
	"github.com/arangodb/go-driver/http"
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
	"github.com/sbezverk/gobmp/pkg/topology/dbclient"
)

var (
	arangoDBConnectTimeout = time.Duration(time.Second * 10)
)

type arangoDB struct {
	user   string
	pass   string
	dbName string
	dbAddr string
	conn   driver.Connection
	client driver.Client
	db     driver.Database
	stop   chan struct{}
	dbclient.DB
}

// NewDBSrvClient returns an instance of a DB server client process
func NewDBSrvClient(arangoSrv, user, pass, dbname string) (dbclient.Srv, error) {
	if err := tools.URLAddrValidation(arangoSrv); err != nil {
		return nil, err
	}
	arango := &arangoDB{
		user:   user,
		pass:   pass,
		dbName: dbname,
		dbAddr: arangoSrv,
		stop:   make(chan struct{}),
	}
	arango.DB = arango

	return arango, nil
}

func (a *arangoDB) Start() error {
	if err := a.connector(); err != nil {
		return err
	}
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

func (a *arangoDB) connector() error {
	conn, err := http.NewConnection(http.ConnectionConfig{
		Endpoints: []string{a.dbAddr},
	})
	if err != nil {
		return err
	}
	c, err := driver.NewClient(driver.ClientConfig{
		Connection:     conn,
		Authentication: driver.BasicAuthentication(a.user, a.pass),
	})
	if err != nil {
		return err
	}
	a.conn = conn
	a.client = c
	ctx, cancel := context.WithTimeout(context.TODO(), arangoDBConnectTimeout)
	defer cancel()
	db, err := c.Database(ctx, a.dbName)
	if err != nil {
		return err
	}
	a.db = db

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
