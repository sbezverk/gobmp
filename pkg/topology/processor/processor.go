package processor

import (
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

type processor struct {
}

// NewProcessorSrv returns an instance of a processor server
func NewProcessorSrv(client dbclient.DB) Srv {
	return &processor{}
}

func (p *processor) Start() error {
	return nil
}

func (p *processor) Stop() error {
	return nil
}

func (p *processor) GetInterface() Messenger {
	return &processor{}
}

func (p *processor) SendMessage(msgType int, msg []byte) {
	return
}
