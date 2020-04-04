package kafkamessenger

import (
	"github.com/sbezverk/gobmp/pkg/topology/processor"
)

// Srv defines required method of a processor server
type Srv interface {
	Start() error
	Stop() error
}

type kafka struct {
}

// NewKafkaMessenger returns an instance of a kafka consumer acting as a messenger server
func NewKafkaMessenger(processor.Messenger) (Srv, error) {
	return &kafka{}, nil
}

func (k *kafka) Start() error {
	return nil
}

func (k *kafka) Stop() error {
	return nil
}
