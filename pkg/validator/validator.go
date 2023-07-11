package validator

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/kafka"
)

type StoredMessage struct {
	TopicType int    `json:"topic_type"`
	Message   []byte `json:"message"`
}

func Check(topics []*kafka.TopicDescriptor, b []byte, errCh chan error) {

	errCh <- nil
}

type message struct {
	msg       []byte
	topicType int
	errCh     chan error
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
			b, _ := json.Marshal(&StoredMessage{TopicType: msg.topicType, Message: msg.msg})
			_, err := s.f.Write(b)
			glog.Infof("storing message, error: %+v", err)
			msg.errCh <- err
		}
	}
}

func (s *store) storeWorker(topic *kafka.TopicDescriptor, done chan struct{}, workersErrChan chan error) {
	for {
		select {
		case <-s.stopCh:
			return
		case msg := <-topic.TopicChan:
			glog.Infof("><SB> Topic: %s received messsage", topic.TopicName)
			errCh := make(chan error)
			s.msgCh <- &message{
				topicType: topic.TopicType,
				msg:       msg,
				errCh:     errCh,
			}
			err := <-errCh
			glog.Infof("><SB> Message processing completed with error: %+v", err)
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
		glog.Infof("><SB> worker reported done...")
		done++
		if done >= total {
			errCh <- nil
			return
		}
	}
}
