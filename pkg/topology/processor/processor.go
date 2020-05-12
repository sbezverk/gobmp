package processor

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/message"
	"github.com/sbezverk/gobmp/pkg/topology/dbclient"
)

// Messenger defines required methonds of a messaging client
type Messenger interface {
	// SendMessage is used by the messanger client to send message to Processor for processing
	SendMessage(msgType int, msg []byte)
}

// Srv defines required method of a processor server
type Srv interface {
	Start() error
	Stop() error
	GetInterface() Messenger
}

type queueMsg struct {
	msgType int
	msgData []byte
}

type processor struct {
	stop  chan struct{}
	queue chan *queueMsg
	db    dbclient.DB
	Messenger
}

// NewProcessorSrv returns an instance of a processor server
func NewProcessorSrv(client dbclient.DB) Srv {
	queue := make(chan *queueMsg)
	p := &processor{
		stop:  make(chan struct{}),
		queue: queue,
		db:    client,
	}
	p.Messenger = p

	return p
}

func (p *processor) Start() error {
	glog.Info("Starting Processor")
	go p.msgProcessor()

	return nil
}

func (p *processor) Stop() error {
	close(p.queue)
	close(p.stop)

	return nil
}

func (p *processor) GetInterface() Messenger {
	return p.Messenger
}

func (p *processor) SendMessage(msgType int, msg []byte) {
	p.queue <- &queueMsg{
		msgType: msgType,
		msgData: msg,
	}
}

func (p *processor) msgProcessor() {
	for {
		select {
		case msg := <-p.queue:
			go p.procWorker(msg)
		case <-p.stop:
			return
		}
	}
}

func (p *processor) procWorker(m *queueMsg) {
	switch m.msgType {
	case bmp.PeerStateChangeMsg:
		var o message.PeerStateChange
		if err := json.Unmarshal(m.msgData, &o); err != nil {
			glog.Errorf("failed to unmarshal message of type %d with error: %+v", m.msgType, err)
			return
		}
		if err := p.db.StoreMessage(m.msgType, &o); err != nil {
			glog.Errorf("failed to store message of type: %d in the database with error: %+v", m.msgType, err)
			return
		}
	case bmp.UnicastPrefixMsg:
		var o message.UnicastPrefix
		if err := json.Unmarshal(m.msgData, &o); err != nil {
			glog.Errorf("failed to unmarshal message of type %d with error: %+v", m.msgType, err)
			return
		}
		if err := p.db.StoreMessage(m.msgType, &o); err != nil {
			glog.Errorf("failed to store message of type: %d in the database with error: %+v", m.msgType, err)
			return
		}
	case bmp.LSNodeMsg:
		var o message.LSNode
		if err := json.Unmarshal(m.msgData, &o); err != nil {
			glog.Errorf("failed to unmarshal message of type %d with error: %+v", m.msgType, err)
			return
		}
		if err := p.db.StoreMessage(m.msgType, &o); err != nil {
			glog.Errorf("failed to store message of type: %d in the database with error: %+v", m.msgType, err)
			return
		}
	case bmp.LSLinkMsg:
		var o message.LSLink
		if err := json.Unmarshal(m.msgData, &o); err != nil {
			glog.Errorf("failed to unmarshal message of type %d with error: %+v", m.msgType, err)
			return
		}
		if err := p.db.StoreMessage(m.msgType, &o); err != nil {
			glog.Errorf("failed to store message of type: %d in the database with error: %+v", m.msgType, err)
			return
		}
	case bmp.LSPrefixMsg:
		var o message.LSPrefix
		if err := json.Unmarshal(m.msgData, &o); err != nil {
			glog.Errorf("failed to unmarshal message of type %d with error: %+v", m.msgType, err)
			return
		}
		if err := p.db.StoreMessage(m.msgType, &o); err != nil {
			glog.Errorf("failed to store message of type: %d in the database with error: %+v", m.msgType, err)
			return
		}
	case bmp.L3VPNMsg:
		var o message.L3VPNPrefix
		if err := json.Unmarshal(m.msgData, &o); err != nil {
			glog.Errorf("failed to unmarshal message of type %d with error: %+v", m.msgType, err)
			return
		}
		if err := p.db.StoreMessage(m.msgType, &o); err != nil {
			glog.Errorf("failed to store message of type: %d in the database with error: %+v", m.msgType, err)
			return
		}
	case bmp.EVPNMsg:
		var o message.EVPNPrefix
		if err := json.Unmarshal(m.msgData, &o); err != nil {
			glog.Errorf("failed to unmarshal message of type %d with error: %+v", m.msgType, err)
			return
		}
		if err := p.db.StoreMessage(m.msgType, &o); err != nil {
			glog.Errorf("failed to store message of type: %d in the database with error: %+v", m.msgType, err)
			return
		}
	}

	glog.V(5).Infof("message of type %d was stored in the database", m.msgType)
}
