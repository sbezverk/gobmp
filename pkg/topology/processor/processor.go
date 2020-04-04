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

type msg struct {
	msgType int
	msgData []byte
}
type processor struct {
	stop  chan struct{}
	queue chan msg
	db    dbclient.DB
}

// NewProcessorSrv returns an instance of a processor server
func NewProcessorSrv(client dbclient.DB) Srv {
	return &processor{
		stop:  make(chan struct{}),
		queue: make(chan msg),
	}
}

func (p *processor) Start() error {
	go p.msgProcessor()

	return nil
}

func (p *processor) Stop() error {
	close(p.stop)
	return nil
}

func (p *processor) GetInterface() Messenger {
	return &processor{}
}

func (p *processor) SendMessage(msgType int, msg []byte) {
	return
}

func (p *processor) msgProcessor() {
	for {
		select {
		case msg := <-p.queue:
			go p.procWorker(msg)
		case <-p.stop:
			return
		default:
		}
	}
}

func (p *processor) procWorker(m msg) {
	var obj interface{}
	if err := json.Unmarshal(m.msgData, &obj); err != nil {
		glog.Errorf("failed to unmarshal message of type %d with error: %+v", err)
		return
	}
	switch m.msgType {
	case bmp.PeerStateChangeMsg:
		if _, ok := obj.(*message.PeerStateChange); !ok {
			glog.Errorf("malformed PeerStateChange message")
			return
		}
	case bmp.LSNodeMsg:
		if _, ok := obj.(*message.LSNode); !ok {
			glog.Errorf("malformed LSNode message")
			return
		}
	case bmp.LSLinkMsg:
		if _, ok := obj.(*message.LSLink); !ok {
			glog.Errorf("malformed LSLink message")
			return
		}
	}
	if err := p.db.StoreMessage(m.msgType, obj); err != nil {
		glog.Errorf("failed to store message of type: %din the database with error: %+v", m.msgType, err)
		return
	}

	glog.Infof("message of type %d was stored in the database", m.msgType)
}
