package mockdb

import (
	"github.com/sbezverk/gobmp/pkg/topology/dbclient"
)

type mockDB struct {
}

// NewDBSrvClient returns an instance of a DB server client process
func NewDBSrvClient(addr string) (dbclient.Srv, error) {
	return &mockDB{}, nil
}

func (m *mockDB) Start() error {
	return nil
}

func (m *mockDB) Stop() error {
	return nil
}
func (m *mockDB) GetInterface() dbclient.DB {
	return &mockDB{}
}

func (m *mockDB) StoreMessage(msgType int, msg interface{}) error {
	return nil
}
