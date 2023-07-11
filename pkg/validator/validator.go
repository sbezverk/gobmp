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

// func GetObject(msgType int, b []byte) (interface{}, error) {
// 	var obj interface{}
// 	switch msgType {
// 	case bmp.UnicastPrefixV4Msg:
// 		fallthrough
// 	case bmp.UnicastPrefixMsg:
// 		fallthrough
// 	case bmp.UnicastPrefixV6Msg:
// 		u := &bmp_message.UnicastPrefix{}
// 		if err := json.Unmarshal(b, u); err != nil {
// 			return nil, err
// 		}
// 		obj = u
// 	case bmp.LSNodeMsg:
// 		fallthrough
// 	case bmp.LSLinkMsg:
// 		fallthrough
// 	case bmp.L3VPNMsg:
// 		fallthrough
// 	case bmp.L3VPNV4Msg:
// 		fallthrough
// 	case bmp.L3VPNV6Msg:
// 		fallthrough
// 	case bmp.LSPrefixMsg:
// 		fallthrough
// 	case bmp.LSSRv6SIDMsg:
// 		fallthrough
// 	case bmp.EVPNMsg:
// 		fallthrough
// 	case bmp.SRPolicyMsg:
// 		fallthrough
// 	case bmp.SRPolicyV4Msg:
// 		fallthrough
// 	case bmp.SRPolicyV6Msg:
// 		fallthrough
// 	case bmp.FlowspecMsg:
// 		fallthrough
// 	case bmp.FlowspecV4Msg:
// 		fallthrough
// 	case bmp.FlowspecV6Msg:
// 		return nil, fmt.Errorf("not yet implmented")
// 	default:
// 		return nil, fmt.Errorf("unknown type %d", msgType)
// 	}

// 	return obj, nil
// }

type StoredMessage struct {
	TopicType uint32
	Len       uint32
	Message   []byte
}

func (sm *StoredMessage) Marshal() []byte {
	b := make([]byte, len(sm.Message)+4+4)
	binary.BigEndian.PutUint32(b[:4], sm.TopicType)
	binary.BigEndian.PutUint32(b[4:8], sm.TopicType)
	copy(b[8:], sm.Message)

	return b
}

func (sm *StoredMessage) Unmarshal(b []byte) error {
	nsm := &StoredMessage{}
	if len(b) < 8 {
		return fmt.Errorf("not enough bytes to unmarshal StoreMessage")
	}
	p := 0
	msgType := binary.BigEndian.Uint32(b[:4])
	nsm.TopicType = msgType
	p += 4
	msgLen := binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	if p+int(msgLen) > len(b) {
		return fmt.Errorf("not enough bytes to unmarshal the message part of StoreMessage")
	}
	nsm.Len = msgLen
	nsm.Message = make([]byte, nsm.Len)
	copy(nsm.Message, b[p:p+int(msgLen)])
	*sm = *nsm

	return nil
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
			_, err := s.f.Write((&StoredMessage{TopicType: uint32(msg.topicType), Len: uint32(len(msg.msg)), Message: msg.msg}).Marshal())
			glog.Infof("storing message, error: %+v", err)
			msg.errCh <- err
		}
	}
}

func (s *store) storeUnicastWorker(topic *kafka.TopicDescriptor, done chan struct{}, workersErrChan chan error) {
	for {
		select {
		case <-s.stopCh:
			return
		case msg := <-topic.TopicChan:
			glog.Infof("><SB> Topic: %s received messsage", topic.TopicName)
			u := &bmp_message.UnicastPrefix{}
			if err := json.Unmarshal(msg, u); err != nil {
				workersErrChan <- err
				return
			}
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
			if u.IsEOR {
				glog.Infof("EoR for topic %s", topic.TopicName)
				done <- struct{}{}
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

	workersErrChan := make(chan error)
	doneCh := make(chan struct{})
	for _, topic := range topics {
		switch topic.TopicType {
		case bmp.UnicastPrefixV4Msg:
			fallthrough
		case bmp.UnicastPrefixMsg:
			fallthrough
		case bmp.UnicastPrefixV6Msg:
			go s.storeUnicastWorker(topic, doneCh, workersErrChan)
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
}
