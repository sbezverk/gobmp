package validator

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/kafka"
	bmp_message "github.com/sbezverk/gobmp/pkg/message"
)

func buildMessgesMap(b []byte) (map[int][][]byte, error) {
	m := make(map[int][][]byte)
	for p := 0; p < len(b); {
		if p+8 > len(b) {
			return nil, fmt.Errorf("invalid length of byte array")
		}
		mt := binary.BigEndian.Uint32(b[p : p+4])
		// Validate message type is in expected range
		// Standard BMP message types: 0-6 (RFC 7854)
		// Internal gobmp message types: 7-116
		if mt > 116 {
			return nil, fmt.Errorf("invalid message type: %d (expected 0-116)", mt)
		}
		p += 4
		ml := binary.BigEndian.Uint32(b[p : p+4])
		p += 4
		if p+int(ml) > len(b) {
			return nil, fmt.Errorf("corrupted data")
		}
		msgs, ok := m[int(mt)]
		if !ok {
			msgs = make([][]byte, 0)
		}
		msgs = append(msgs, b[p:p+int(ml)])
		m[int(mt)] = msgs
		p += int(ml)
	}
	for mt, msgs := range m {
		glog.Infof("For message type %d, %d messages found", mt, len(msgs))
	}

	return m, nil
}

type check struct {
	stopCh chan struct{}
}

func makeUnicastPrefixKey(u *bmp_message.UnicastPrefix) (string, error) {
	if u == nil {
		return "", fmt.Errorf("object is nil")
	}
	return u.Prefix + "_" + strconv.Itoa(int(u.PrefixLen)) + "_" + u.PeerIP + "_" + u.Nexthop, nil
}

func (c *check) checkUnicastWorker(testMsgs [][]byte, topic *kafka.TopicDescriptor, done chan struct{}, workersErrChan chan error) {
	// Preparing message dictionary
	dictionary := make(map[string]*bmp_message.UnicastPrefix)
	for _, tm := range testMsgs {
		u := &bmp_message.UnicastPrefix{}
		if err := json.Unmarshal(tm, u); err != nil {
			workersErrChan <- err
			return
		}
		if u.IsEOR {
			continue
		}
		k, err := makeUnicastPrefixKey(u)
		if err != nil {
			workersErrChan <- err
			return
		}
		// Check for duplicate keys in test data
		if _, exists := dictionary[k]; exists {
			workersErrChan <- fmt.Errorf("duplicate key found in test data: %s", k)
			return
		}
		dictionary[k] = u
	}
	glog.Infof("Dictionaly for topic type %d contains %d test messages", topic.TopicType, len(dictionary))
	matches := 0
	for {
		select {
		case <-c.stopCh:
			return
		case msg := <-topic.TopicChan:
			glog.Infof("Check received message from topic type: %d", topic.TopicType)
			ou := &bmp_message.UnicastPrefix{}
			if err := json.Unmarshal(msg, ou); err != nil {
				workersErrChan <- err
				return
			}
			if ou.IsEOR {
				continue
			}
			k, err := makeUnicastPrefixKey(ou)
			if err != nil {
				workersErrChan <- err
				return
			}
			u, ok := dictionary[k]
			if !ok {
				workersErrChan <- fmt.Errorf("dictionary does not have a test message for key: %s", k)
				return
			}
			glog.Infof("found matching the test message for the key: %s", k)
			equal, diffs := u.Equal(ou)
			if !equal {
				workersErrChan <- fmt.Errorf("for key: %s, expected and received messages differ, diffs: %s", k, strings.Join(diffs, " | "))
				return
			}
			matches++
			if matches >= len(dictionary) {
				// All checks are completed, exiting
				glog.Infof("topic type %d, all checks are done.", topic.TopicType)
				done <- struct{}{}
				return
			}
		}
	}
}

func Check(topics []*kafka.TopicDescriptor, b []byte, stopCh chan struct{}, errCh chan error) {
	msgs, err := buildMessgesMap(b)
	if err != nil {
		errCh <- err
		return
	}
	c := &check{
		stopCh: make(chan struct{}),
	}
	doneCh := make(chan struct{})
	workersErrChan := make(chan error)
	for _, topic := range topics {
		topicMsgs, ok := msgs[topic.TopicType]
		if !ok {
			// Ddid not find corresponding to the topic type test messages
			errCh <- fmt.Errorf("no test messages for topic type: %d were found the tests data", topic.TopicType)
			return
		}
		switch topic.TopicType {
		case bmp.UnicastPrefixV4Msg:
			fallthrough
		case bmp.UnicastPrefixMsg:
			fallthrough
		case bmp.UnicastPrefixV6Msg:
			go c.checkUnicastWorker(topicMsgs, topic, doneCh, workersErrChan)
		}
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
	errCh <- nil
}
