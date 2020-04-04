package arangodb

import (
	"github.com/sbezverk/gobmp/pkg/topology/dbclient"
)

type arangoDB struct {
}

// NewDBSrvClient returns an instance of a DB server client process
func NewDBSrvClient(addr string) (dbclient.Srv, error) {
	return &arangoDB{}, nil
}

func (a *arangoDB) Start() error {
	return nil
}

func (a *arangoDB) Stop() error {
	return nil
}
func (a *arangoDB) GetInterface() dbclient.DB {
	return &arangoDB{}
}

func (a *arangoDB) AddRecord(recordType int, record interface{}) error {
	return nil
}

func (a *arangoDB) DelRecord(recordType int, record interface{}) error {
	return nil
}
