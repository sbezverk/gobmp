package validator

import (
	"fmt"
	"os"

	"github.com/sbezverk/gobmp/pkg/kafka"
)

func Check(topics []*kafka.TopicDescriptor, b []byte, errCh chan error) {

	errCh <- nil
}

type message struct {
	msg   []byte
	errCh chan error
}
type store struct {
	stopCh chan struct{}
	msgCh  chan *message
	errCh  chan error
	f      *os.File
}

func (s *store) manager() {
	for {
		select {
		case <-s.stopCh:
			return
		case msg := <-s.msgCh:
			_, err := s.f.Write(msg.msg)
			s.errCh <- err
		}
	}
}

func (s *store) storeWorker(topic *kafka.TopicDescriptor, done chan struct{}, workersErrChan chan error) {
	for {
		select {
		case <-s.stopCh:
			return
		case msg := <-topic.TopicChan:
			errCh := make(chan error)
			s.msgCh <- &message{
				msg:   msg,
				errCh: errCh,
			}
			err := <-errCh
			if err != nil {
				workersErrChan <- err
				return
			}

			// TODO (sbezverk) investigate EoR message to indicate complition of a worker and to send done signal
		}
	}
}

func Store(topics []*kafka.TopicDescriptor, f *os.File, stopCh chan struct{}, errCh chan error) {
	if f == nil {
		errCh <- fmt.Errorf("file object cannot be nil")
		return
	}
	s := &store{
		f:      f,
		errCh:  errCh,
		stopCh: make(chan struct{}),
		msgCh:  make(chan *message),
	}
	go s.manager()
	defer close(s.stopCh)

	workersErrChan := make(chan error)
	doneCh := make(chan struct{})
	for _, topic := range topics {
		go s.storeWorker(topic, doneCh, workersErrChan)
	}

	total := len(topics)
	done := 0
	select {
	case <-stopCh:
		return
	case err := <-workersErrChan:
		errCh <- err
		return
	case <-doneCh:
		done++
		if done >= total {
			errCh <- nil
			return
		}
	}
}
