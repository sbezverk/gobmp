package mockdb

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/message"
	"github.com/sbezverk/gobmp/pkg/topology/dbclient"
)

type mockDB struct {
	stop chan struct{}
	dbclient.DB
}

// NewDBSrvClient returns an instance of a mock DB server client process
func NewDBSrvClient(addr string) (dbclient.Srv, error) {
	m := &mockDB{
		stop: make(chan struct{}),
	}
	m.DB = m

	return m, nil
}

func (m *mockDB) Start() error {
	glog.Info("Starting Mock DB Client")
	return nil
}

func (m *mockDB) Stop() error {
	close(m.stop)

	return nil
}

func (m *mockDB) GetInterface() dbclient.DB {
	return m.DB
}

func (m *mockDB) StoreMessage(msgType int, msg interface{}) error {
	switch msgType {
	case bmp.PeerStateChangeMsg:
		p, ok := msg.(*message.PeerStateChange)
		if !ok {
			return fmt.Errorf("malformed PeerStateChange message")
		}
		go m.peerChangeHandler(p)
	case bmp.LSNodeMsg:
		ln, ok := msg.(*message.LSNode)
		if !ok {
			return fmt.Errorf("malformed LSNode message")
		}
		go m.lsNodeHandler(ln)
	case bmp.LSLinkMsg:
		ll, ok := msg.(*message.LSLink)
		if !ok {
			return fmt.Errorf("malformed LSLink message")
		}
		go m.lsLinkHandler(ll)
	}

	return nil
}

func (m *mockDB) peerChangeHandler(obj *message.PeerStateChange) {
	glog.Infof("><SB> peer change handler")
}

func (m *mockDB) lsNodeHandler(obj *message.LSNode) {
	glog.Infof("><SB> LS Node handler")
}

func (m *mockDB) lsLinkHandler(obj *message.LSLink) {
	glog.Infof("><SB> LS Link handler")
}
