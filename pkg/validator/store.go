package validator

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/kafka"
	bmp_message "github.com/sbezverk/gobmp/pkg/message"
)

type StoredMessage struct {
	TopicType uint32
	Len       uint32
	Message   []byte
}

func (sm *StoredMessage) Marshal() []byte {
	b := make([]byte, len(sm.Message)+4+4)
	binary.BigEndian.PutUint32(b[:4], sm.TopicType)
	binary.BigEndian.PutUint32(b[4:8], sm.Len)
	copy(b[8:], sm.Message)

	return b
}

func (sm *StoredMessage) Unmarshal(b []byte) error {
	nsm := &StoredMessage{}
	if len(b) < 8 {
		return fmt.Errorf("not enough bytes to unmarshal StoredMessage, need at least 8 bytes for topic type and length, got %d", len(b))
	}
	p := 0
	msgType := binary.BigEndian.Uint32(b[:4])
	nsm.TopicType = msgType
	p += 4
	msgLen := binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	if p+int(msgLen) > len(b) {
		return fmt.Errorf("not enough bytes to unmarshal the message part of StoredMessage, need %d bytes, got %d", msgLen, len(b)-p)
	}
	nsm.Len = msgLen
	nsm.Message = make([]byte, nsm.Len)
	copy(nsm.Message, b[p:p+int(msgLen)])
	*sm = *nsm

	return nil
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
			_, err := s.f.Write((&StoredMessage{TopicType: uint32(msg.topicType), Len: uint32(len(msg.msg)), Message: msg.msg}).Marshal())
			msg.errCh <- err
		}
	}
}

func (s *store) storeUnicastWorker(topic *kafka.TopicDescriptor, workersErrChan chan error) {
	for {
		select {
		case <-s.stopCh:
			return
		case msg := <-topic.TopicChan:
			glog.Infof("Store received message from topic type: %d", topic.TopicType)
			u := &bmp_message.UnicastPrefix{}
			if err := json.Unmarshal(msg, u); err != nil {
				workersErrChan <- err
				return
			}
			if u.IsEOR {
				continue
			}
			errCh := make(chan error, 1)
			select {
			case s.msgCh <- &message{
				topicType: topic.TopicType,
				msg:       msg,
				errCh:     errCh,
			}:
			case <-s.stopCh:
				return
			}
			select {
			case err := <-errCh:
				if err != nil {
					select {
					case workersErrChan <- err:
					case <-s.stopCh:
					}
				}
			case <-s.stopCh:
				return
			}
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

	workersErrChan := make(chan error, len(topics))
	for _, topic := range topics {
		switch topic.TopicType {
		case bmp.UnicastPrefixV4Msg:
			fallthrough
		case bmp.UnicastPrefixMsg:
			fallthrough
		case bmp.UnicastPrefixV6Msg:
			go s.storeUnicastWorker(topic, workersErrChan)
		}
	}
	select {
	case <-stopCh:
		return
	case err := <-workersErrChan:
		errCh <- err
		return
	}
}
